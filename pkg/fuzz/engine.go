package fuzz

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/replay"
)

// calibrationProbes are improbable values sent to learn the target's
// catch-all/wildcard response before real fuzzing. Fixed (not random) so a run
// is reproducible; chosen to be things no real route or file would match.
var calibrationProbes = []string{
	"vigolium-calibrate-9x1q7",
	"vigolium-calibrate-zzq4t",
	"vigolium-calibrate-0k8wm",
}

// Run executes the job: send the baseline, optionally calibrate, then fan out
// every (position, payload) pair through replay.SendRaw, gating each result and
// streaming it via job.OnResult. It returns once every send completes.
func Run(ctx context.Context, job Job) (*Report, error) {
	if job.Client == nil && job.Sender == nil {
		return nil, fmt.Errorf("fuzz.Run: job.Client or job.Sender is required")
	}
	if job.Hostname == "" {
		return nil, fmt.Errorf("fuzz.Run: job.Hostname is required")
	}
	plan := job.Plan
	if plan == nil && len(job.Cases) > 0 {
		plan = CaseSlice(job.Cases)
	}
	if plan == nil {
		if len(job.Positions) == 0 {
			return nil, fmt.Errorf("fuzz.Run: no positions to fuzz")
		}
		if len(job.Payloads) == 0 {
			return nil, fmt.Errorf("fuzz.Run: no payloads")
		}
		// No explicit plan: the historical positions x payloads expansion,
		// which is exactly sniper — walked lazily, never materialized.
		p, err := BuildPlan(ModeSniper, job.Positions, nil, job.Payloads)
		if err != nil {
			return nil, fmt.Errorf("fuzz.Run: %w", err)
		}
		plan = p
	}

	// Guarantee a parseable request regardless of how the caller assembled it
	// (e.g. a line-trimming stdin reader can strip the header terminator).
	job.Raw = NormalizeRawRequest(job.Raw)

	excerptCap := job.ExcerptCap
	if excerptCap <= 0 {
		excerptCap = replay.DefaultExcerptCap
	}
	// send routes through the caller's Sender (e.g. the Burp bridge) when set,
	// else the built-in replay.SendRaw transport — every send in the run (baseline,
	// calibration, payloads) shares this one closure.
	//
	// The rate limiter sits inside this closure for the same reason: wrapping
	// the one send path is what guarantees baseline samples and calibration
	// probes are paced exactly like payloads.
	limiter := newRateLimiter(job.RateLimit)
	send := func(raw []byte) *replay.Summary {
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return &replay.Summary{Error: err.Error()}
			}
		}
		if job.Sender != nil {
			return job.Sender(ctx, raw)
		}
		return replay.SendRaw(ctx, job.Client, raw, job.Scheme, job.Hostname, job.Port, job.NoRedirects, excerptCap)
	}

	// Baseline — the un-fuzzed request, for delta reporting and calibration.
	baseSum, baseline := sampleBaseline(ctx, job, send)
	report := &Report{Baseline: baseline}
	if baseline.Samples == 0 && !job.AllowBaselineError {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		return report, fmt.Errorf("fuzz.Run: baseline request failed (%s); "+
			"every delta and the calibration would compare against nothing — fix the request or allow it explicitly",
			baseline.Error)
	}

	var detect *detector
	if job.Anomaly != nil {
		detect = newDetector(*job.Anomaly, report.Baseline, baseSum.Headers, baseSum.RawBody)
	}

	var calib *calibrator
	if job.AutoCalibrate {
		calib = newCalibrator(ctx, job.Raw, send)
	}

	concurrency := job.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, concurrency)
		// pending retains each result's evidence for the second anomaly pass.
		// Only populated when detection is on, since it holds response bodies.
		pending []pendingResult
	)

	for i, n := 0, plan.Len(); i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		c := plan.At(i)
		wg.Add(1)
		sem <- struct{}{}
		go func(c Case) {
			defer wg.Done()
			defer func() { <-sem }()

			if job.DelayMs > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(job.DelayMs) * time.Millisecond):
				}
			}

			{
				built := c.build(job.Raw)
				sum := send(built)
				res := makeResult(c, sum, report.Baseline, calib, job.Matchers, job.Filters)

				var baseScore int
				var baseReason []AnomalyReason
				if detect != nil {
					detect.observe(&res)
					baseScore, baseReason = detect.baselineSignals(&res, sum.RawBody, sum.Headers)

					// Provisional verdict: the population is still forming, so
					// only its O(1) half is consulted here. rescoreAnomalies
					// redoes this against the finished population.
					popScore, popReason := detect.populationSignals(&res, detect.snapshot(false))
					res.AnomalyScore = baseScore + popScore
					res.AnomalyReasons = append(append([]AnomalyReason(nil), baseReason...), popReason...)

					// With detection on and no explicit matchers, "interesting"
					// replaces "everything" as the default keep rule — which is
					// the entire point of --anomaly.
					if !job.Matchers.configured() {
						res.Matched = !res.Calibrated && res.AnomalyScore >= detect.cfg.Threshold
					}
				}

				mu.Lock()
				if detect != nil {
					pending = append(pending, pendingResult{
						result:     res,
						baseScore:  baseScore,
						baseReason: baseReason,
					})
				}
				report.Sent++
				if res.Error != "" {
					report.Errors++
				}
				if res.Calibrated {
					report.Calibrated++
				}
				if res.Matched {
					report.Matched++
					if job.OnMatch != nil {
						job.OnMatch(res, built)
					}
				}
				if job.OnResult != nil {
					job.OnResult(res)
				}
				mu.Unlock()
			}
		}(c)
	}

	wg.Wait()
	if detect != nil {
		report.Anomalies = rescoreAnomalies(detect, pending, job, report)
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}

// newRateLimiter returns a smooth (burst 1) limiter for rps requests per
// second, or nil when rps is not positive (unlimited).
func newRateLimiter(rps float64) *rate.Limiter {
	if rps <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(rps), 1)
}

// makeResult builds one Result: extract signals, compute baseline deltas and
// reflection, apply the matcher/filter gate, and fold in calibration.
func makeResult(c Case, sum *replay.Summary, base Baseline, calib *calibrator, m Matchers, f Filters) Result {
	status, length, words, lines := signals(sum)
	position, positionType, payload := c.label()
	// Reflection is checked per assigned payload, so a multi-position case
	// reports a hit when any of its payloads came back.
	var anyRefl, rawRefl bool
	var where []string
	for _, a := range c.Assignments {
		hit, raw, w := reflectionOf(sum.RawBody, sum.Headers, a.Payload)
		anyRefl = anyRefl || hit
		rawRefl = rawRefl || raw
		where = append(where, w...)
	}
	where = dedupeStrings(where)
	res := Result{
		Position:      position,
		PositionType:  positionType,
		Payload:       payload,
		Status:        status,
		Length:        length,
		Words:         words,
		Lines:         lines,
		TimeMs:        sum.ResponseTimeMs,
		ContentHash:   sum.ContentHash,
		Reflected:     anyRefl,
		ReflectedRaw:  rawRefl,
		ReflectedIn:   where,
		StatusChanged: status != base.Status,
		LengthDelta:   length - base.Length,
		TimeZ:         timeZ(sum.ResponseTimeMs, base),
		Error:         sum.Error,
	}
	if res.Error != "" {
		return res
	}
	if len(c.Assignments) > 0 {
		res.Calibrated = calib.forPosition(c.Assignments[0].Position).matches(status, length, words)
	}
	res.Matched = !res.Calibrated && keep(res, sum.RawBody, sum.Headers, m, f)
	return res
}

// sampleBaseline sends the un-fuzzed request BaselineSamples times and folds
// the results into one Baseline, returning the last summary (for calibration
// and anomaly seeding) alongside it.
//
// More than one sample exists purely for timing. A single measurement can't
// separate "the payload made the server work" from ordinary network jitter, so
// a time-based signal built on one sample is either deaf or full of false
// positives. Sampling gives a mean and a deviation, and TimeZ then says how
// unusual a response is *for this endpoint* instead of against a millisecond
// threshold guessed in advance.
func sampleBaseline(ctx context.Context, job Job, send func([]byte) *replay.Summary) (*replay.Summary, Baseline) {
	samples := job.BaselineSamples
	if samples < 1 {
		samples = 1
	}

	var (
		last  *replay.Summary
		times []int64
	)
	for i := 0; i < samples; i++ {
		if i > 0 && ctx.Err() != nil {
			break
		}
		last = send(job.Raw)
		if last.Error == "" {
			times = append(times, last.ResponseTimeMs)
		}
	}

	status, length, words, lines := signals(last)
	b := Baseline{
		Status: status, Length: length, Words: words, Lines: lines,
		Hash: last.ContentHash, Error: last.Error,
		Samples: len(times),
	}
	b.TimeMs, b.TimeStdDev = meanStdDev(times)
	if len(times) > 1 {
		b.TimeSamples = times
	}
	return last, b
}

// meanStdDev returns the mean and population standard deviation of a set of
// millisecond samples, delegating to the shared timing helper that the module
// scanner uses to derive its adaptive delay thresholds.
func meanStdDev(ms []int64) (mean int64, stddev float64) {
	if len(ms) == 0 {
		return 0, 0
	}
	durations := make([]time.Duration, len(ms))
	for i, v := range ms {
		durations[i] = time.Duration(v) * time.Millisecond
	}
	m, sd := infra.MeanStdev(durations)
	return int64(m / time.Millisecond), float64(sd) / float64(time.Millisecond)
}

// timeZ scores a response time in baseline standard deviations. It needs a
// real deviation to divide by; a floor of 1ms keeps a perfectly consistent
// baseline (stddev 0, common on localhost) from producing an infinite z for a
// 1ms wobble.
func timeZ(timeMs int64, base Baseline) float64 {
	if base.Samples < 2 {
		return 0
	}
	sd := base.TimeStdDev
	if sd < 1 {
		sd = 1
	}
	return float64(timeMs-base.TimeMs) / sd
}

// pendingResult holds one result and its already-computed baseline score,
// ready for the population half to be added once the run finishes.
//
// It deliberately holds no response body: retaining one per send meant a 50k
// -send run against 100KB responses sat on ~5GB, and nothing the second pass
// computes actually needs the body — every population signal reads a field
// that is already on Result.
type pendingResult struct {
	result     Result
	baseScore  int
	baseReason []AnomalyReason
}

// rescoreAnomalies is the second detection pass. Every result is scored again
// against the finished population, so a run's verdicts don't depend on the
// order sends happened to complete in — the first result and the last are
// judged against the same statistics.
//
// It returns the anomalies sorted most-interesting first, and reconciles the
// report counters with the final verdicts.
func rescoreAnomalies(detect *detector, pending []pendingResult, job Job, report *Report) []Result {
	matchersConfigured := job.Matchers.configured()

	// One snapshot for the whole pass: the population is final, so the
	// medians it sorts for are the same for every result.
	stats := detect.snapshot(true)

	var anomalies []Result
	matched := 0
	for i := range pending {
		p := &pending[i]
		popScore, popReason := detect.populationSignals(&p.result, stats)
		p.result.AnomalyScore = p.baseScore + popScore
		p.result.AnomalyReasons = append(append([]AnomalyReason(nil), p.baseReason...), popReason...)
		if !matchersConfigured {
			p.result.Matched = !p.result.Calibrated && p.result.AnomalyScore >= detect.cfg.Threshold
		}
		if p.result.Matched {
			matched++
		}
		if p.result.AnomalyScore >= detect.cfg.Threshold && !p.result.Calibrated {
			anomalies = append(anomalies, p.result)
		}
	}
	report.Matched = matched

	sort.SliceStable(anomalies, func(i, j int) bool {
		return anomalies[i].AnomalyScore > anomalies[j].AnomalyScore
	})
	if len(anomalies) > MaxReportedAnomalies {
		report.AnomaliesElided = len(anomalies) - MaxReportedAnomalies
		anomalies = anomalies[:MaxReportedAnomalies]
	}
	return anomalies
}

// MaxReportedAnomalies bounds how many anomalies the report carries, so a
// pathological run can't return a copy of every response body's worth of
// metadata.
const MaxReportedAnomalies = 100

// calibrator learns catch-all signatures per position, lazily, the first time
// a case at that position is about to be judged. One position's catch-all says
// nothing about another's: a path segment's 404 page and a query parameter's
// "invalid value" page are different shapes, and calibrating only the first
// position left every later one uncalibrated.
type calibrator struct {
	ctx  context.Context
	raw  []byte
	send func([]byte) *replay.Summary

	mu    sync.Mutex
	byPos map[string]*calibEntry
}

type calibEntry struct {
	once sync.Once
	c    *calibration
}

func newCalibrator(ctx context.Context, raw []byte, send func([]byte) *replay.Summary) *calibrator {
	return &calibrator{ctx: ctx, raw: raw, send: send, byPos: make(map[string]*calibEntry)}
}

// forPosition returns the position's calibration, learning it on first use.
// Concurrent callers for the same position wait for the one learner.
func (c *calibrator) forPosition(pos Position) *calibration {
	if c == nil {
		return nil
	}
	key := pos.Label + "\x00" + pos.Name
	c.mu.Lock()
	e, ok := c.byPos[key]
	if !ok {
		e = &calibEntry{}
		c.byPos[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.c = calibrate(c.ctx, c.raw, pos, c.send) })
	return e.c
}

// calibrate sends the improbable probes at one position and records any
// signature (status, word count, length bucket) a majority of probes share as
// that position's wildcard fingerprint.
func calibrate(ctx context.Context, raw []byte, pos Position, send func([]byte) *replay.Summary) *calibration {
	if ctx.Err() != nil {
		return nil
	}
	type cluster struct {
		sig calibSig
		n   int
	}
	var clusters []cluster
	for _, probe := range calibrationProbes {
		if ctx.Err() != nil {
			break
		}
		sum := send(pos.build(raw, probe))
		if sum.Error != "" {
			continue
		}
		status, length, words, _ := signals(sum)
		placed := false
		for i := range clusters {
			if clusters[i].sig.matches(status, length, words) {
				clusters[i].n++
				placed = true
				break
			}
		}
		if !placed {
			clusters = append(clusters, cluster{sig: calibSig{status: status, length: length, words: words}, n: 1})
		}
	}
	threshold := (len(calibrationProbes) + 1) / 2 // majority
	c := &calibration{}
	for _, cl := range clusters {
		if cl.n >= threshold {
			c.sigs = append(c.sigs, cl.sig)
		}
	}
	if len(c.sigs) == 0 {
		return nil
	}
	return c
}
