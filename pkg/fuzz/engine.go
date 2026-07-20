package fuzz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

// calibrationProbes are improbable values sent to learn the target's
// catch-all/wildcard response before real fuzzing. Fixed (not random) so a run
// is reproducible; chosen to be things no real route or file would match.
var calibrationProbes = []string{
	"vglm-calibrate-9x1q7",
	"vglm-calibrate-zzq4t",
	"vglm-calibrate-0k8wm",
}

// Run executes the job: send the baseline, optionally calibrate, then fan out
// every (position, payload) pair through replay.SendRaw, gating each result and
// streaming it via job.OnResult. It returns once every send completes.
func Run(ctx context.Context, job Job) (*Report, error) {
	if job.Client == nil {
		return nil, fmt.Errorf("fuzz.Run: job.Client is required")
	}
	if job.Hostname == "" {
		return nil, fmt.Errorf("fuzz.Run: job.Hostname is required")
	}
	if len(job.Positions) == 0 {
		return nil, fmt.Errorf("fuzz.Run: no positions to fuzz")
	}
	if len(job.Payloads) == 0 {
		return nil, fmt.Errorf("fuzz.Run: no payloads")
	}

	// Guarantee a parseable request regardless of how the caller assembled it
	// (e.g. a line-trimming stdin reader can strip the header terminator).
	job.Raw = NormalizeRawRequest(job.Raw)

	excerptCap := job.ExcerptCap
	if excerptCap <= 0 {
		excerptCap = replay.DefaultExcerptCap
	}
	send := func(raw []byte) *replay.Summary {
		return replay.SendRaw(ctx, job.Client, raw, job.Scheme, job.Hostname, job.Port, job.NoRedirects, excerptCap)
	}

	// Baseline — the un-fuzzed request, for delta reporting and calibration.
	baseSum := send(job.Raw)
	bStatus, bLen, bWords, bLines := signals(baseSum)
	report := &Report{Baseline: Baseline{
		Status: bStatus, Length: bLen, Words: bWords, Lines: bLines,
		Hash: baseSum.ContentHash, Error: baseSum.Error,
	}}

	var calib *calibration
	if job.AutoCalibrate {
		calib = calibrate(ctx, job, send)
	}

	concurrency := job.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, concurrency)
	)

	for _, pos := range job.Positions {
		for _, payload := range job.Payloads {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(pos Position, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				if job.DelayMs > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(job.DelayMs) * time.Millisecond):
					}
				}

				sum := send(pos.build(job.Raw, payload))
				res := makeResult(pos, payload, sum, report.Baseline, calib, job.Matchers, job.Filters)

				mu.Lock()
				report.Sent++
				if res.Error != "" {
					report.Errors++
				}
				if res.Calibrated {
					report.Calibrated++
				}
				if res.Matched {
					report.Matched++
				}
				if job.OnResult != nil {
					job.OnResult(res)
				}
				mu.Unlock()
			}(pos, payload)
		}
	}

	wg.Wait()
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}

// makeResult builds one Result: extract signals, compute baseline deltas and
// reflection, apply the matcher/filter gate, and fold in calibration.
func makeResult(pos Position, payload string, sum *replay.Summary, base Baseline, calib *calibration, m Matchers, f Filters) Result {
	status, length, words, lines := signals(sum)
	res := Result{
		Position:      pos.Name,
		PositionType:  pos.Label,
		Payload:       payload,
		Status:        status,
		Length:        length,
		Words:         words,
		Lines:         lines,
		TimeMs:        sum.ResponseTimeMs,
		ContentHash:   sum.ContentHash,
		Reflected:     reflected(sum.RawBody, payload),
		StatusChanged: status != base.Status,
		LengthDelta:   length - base.Length,
		Error:         sum.Error,
	}
	if res.Error != "" {
		return res
	}
	res.Calibrated = calib.matches(status, length)
	res.Matched = !res.Calibrated && keep(res, sum.RawBody, m, f)
	return res
}

// calibrate sends the improbable probes at the first position and records any
// (status,length) signature seen by a majority of probes as the wildcard
// fingerprint.
func calibrate(ctx context.Context, job Job, send func([]byte) *replay.Summary) *calibration {
	if ctx.Err() != nil {
		return nil
	}
	pos := job.Positions[0]
	counts := make(map[calibSig]int)
	for _, probe := range calibrationProbes {
		if ctx.Err() != nil {
			break
		}
		sum := send(pos.build(job.Raw, probe))
		if sum.Error != "" {
			continue
		}
		counts[calibSig{status: sum.Status, length: sum.ResponseLen}]++
	}
	threshold := (len(calibrationProbes) + 1) / 2 // majority
	c := &calibration{sigs: make(map[calibSig]struct{})}
	for sig, n := range counts {
		if n >= threshold {
			c.sigs[sig] = struct{}{}
		}
	}
	if len(c.sigs) == 0 {
		return nil
	}
	return c
}
