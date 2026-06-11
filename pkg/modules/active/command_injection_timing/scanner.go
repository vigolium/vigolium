package command_injection_timing

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// baselineSamples is how many unmodified requests model the target's normal
	// response-time distribution before any sleep payload is tested.
	baselineSamples = 4
	// timeStdevCoeff multiplies the baseline standard deviation when deriving the
	// delay threshold (mirrors sqli_time_blind: sensitive but clear of jitter).
	timeStdevCoeff = 5
	// minSleepMargin is the minimum absolute delay above the baseline mean a sleep
	// payload must add before it is believed (guards low-variance hosts).
	minSleepMargin = 3 * time.Second
	// absoluteFloor is a hard lower bound on the threshold so a near-instant
	// baseline can never let trivial jitter masquerade as an injection.
	absoluteFloor = 2 * time.Second
	// maxThreshold caps the derived threshold: a host so slow/jittery that the
	// threshold exceeds this can't be tested reliably with the sleepHigh payload.
	maxThreshold = 9 * time.Second

	// sleepHigh / sleepLow are the two requested sleep durations used to prove the
	// response delay scales with the injected value.
	sleepHigh = 6
	sleepLow  = 2
	// timeRounds is how many independent confirmation rounds must ALL pass. Timing
	// is the weakest, most network-sensitive oracle: a transient spike (GC pause,
	// scheduler stall, packet loss/retransmit) can make a single high-sleep probe
	// look slow. Requiring the full scaling check to reproduce across several
	// independent rounds makes such a one-off spike vanishingly unlikely to be
	// mistaken for an injection.
	timeRounds = 3
)

// Module implements the time-based (delay-scaling) OS command injection scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new delay-scaling command injection module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyDefaultRHM("command_injection_timing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests all insertion points for delay-scaling command injection.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	templates := infra.CmdiSleepTemplates()

ipScan:
	for _, ip := range points {
		baseValue := ip.BaseValue()

		threshold, err := m.deriveThreshold(ctx, httpClient, ip)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if threshold > maxThreshold {
			continue // Target too slow/jittery to time-test reliably
		}

		for _, tmpl := range templates {
			result, err := m.confirmTiming(ctx, httpClient, ip, tmpl, baseValue, threshold)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}
			if result != nil {
				result.URL = urlx.String()
				result.Matched = urlx.String()
				results = append(results, result)
				continue ipScan
			}
		}
	}

	return results, nil
}

// deriveThreshold samples the insertion point's unmodified latency and returns
// the delay a sleep payload must exceed to be believed:
// max(absoluteFloor, mean + max(coeff·stdev, minSleepMargin)).
func (m *Module) deriveThreshold(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
) (time.Duration, error) {
	base := ip.BaseValue()
	samples := make([]time.Duration, 0, baselineSamples)
	for i := 0; i < baselineSamples; i++ {
		d, err := m.sendTimedPayload(ctx, httpClient, ip, base, false)
		if err != nil {
			return 0, err
		}
		samples = append(samples, d.elapsed)
	}

	mean, stdev := infra.MeanStdev(samples)
	margin := time.Duration(timeStdevCoeff) * stdev
	if margin < minSleepMargin {
		margin = minSleepMargin
	}
	threshold := mean + margin
	if threshold < absoluteFloor {
		threshold = absoluteFloor
	}
	return threshold, nil
}

// confirmTiming confirms time-based command injection across multiple rounds and
// verifies the observed delay tracks the requested sleep duration. The scaling
// factor is the decisive false-positive killer: random slowness or a
// fixed-timeout/retry sink does not produce a delay that grows linearly with the
// sleep argument.
func (m *Module) confirmTiming(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	tmpl infra.CmdiSleepTemplate,
	baseValue string,
	threshold time.Duration,
) (*output.ResultEvent, error) {
	render := func(seconds int) string { return baseValue + tmpl.Render(seconds) }

	// roundTiming records one confirmation round's measured latencies so the
	// multi-round scaling comparison that proves the finding is preserved as
	// evidence rather than recomputed and thrown away.
	type roundTiming struct{ noSleep, low, high time.Duration }
	var rounds []roundTiming
	// The no-sleep control (fast) and high-sleep proof (slow) from the final
	// round, captured with their raw request/response for the finding's evidence.
	var control, proof timedResult

	for round := 0; round < timeRounds; round++ {
		// Capture request/response on the final round only — earlier rounds just
		// gate, so reading their bodies would waste allocations on the hot path.
		capture := round == timeRounds-1

		noSleep, err := m.sendTimedPayload(ctx, httpClient, ip, render(0), capture)
		if err != nil {
			return nil, err
		}
		if noSleep.elapsed >= threshold {
			return nil, nil // Host is uniformly slow — not a reliable signal
		}

		high, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepHigh), capture)
		if err != nil {
			return nil, err
		}
		if high.elapsed < threshold {
			return nil, nil // No delay from the high sleep payload
		}

		low, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepLow), false)
		if err != nil {
			return nil, err
		}
		// The low sleep must itself add a partial delay (rules out a one-off spike
		// on the high request)...
		if low.elapsed < time.Duration(sleepLow)*time.Second/2 {
			return nil, nil
		}
		// ...and the high−low differential must track the requested (high−low)
		// seconds (at least half, allowing for overhead/jitter).
		observed := high.elapsed - low.elapsed
		expected := time.Duration(sleepHigh-sleepLow) * time.Second
		if observed < expected/2 {
			return nil, nil
		}

		rounds = append(rounds, roundTiming{noSleep.elapsed, low.elapsed, high.elapsed})
		if capture {
			control, proof = noSleep, high
		}
	}

	// All rounds passed — confirmed delay-scaling command injection. Carry the
	// differential that proves it: the slow high-sleep probe is the primary pair,
	// with the unmodified baseline and the fast no-sleep control as evidence.
	// proof/control are always populated here: the final round captures, and the
	// loop only reaches this point once every round has passed.
	sleepPayload := render(sleepHigh)

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (unmodified request)", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
	ev.Add("control: no-sleep payload returned fast", control.request, control.response)

	extracted := []string{sleepPayload, render(0), tmpl.Label}
	for i, r := range rounds {
		extracted = append(extracted, fmt.Sprintf(
			"Round %d: no-sleep %dms, %ds-sleep %dms, %ds-sleep %dms",
			i+1, r.noSleep.Milliseconds(), sleepLow, r.low.Milliseconds(), sleepHigh, r.high.Milliseconds()))
	}

	last := rounds[len(rounds)-1]
	return &output.ResultEvent{
		Request:            proof.request,
		Response:           proof.response,
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   extracted,
		AdditionalEvidence: ev.Entries(),
		MatcherStatus:      true,
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf(
				"Possible time-based blind OS command injection in parameter %q: the response delay "+
					"scaled with the injected sleep duration above an adaptive per-target threshold "+
					"across %d independent rounds via the %s payload (final round: no-sleep %dms, "+
					"%ds-sleep %dms, %ds-sleep %dms). Detection is purely timing-based and can still be "+
					"influenced by network conditions — corroborate with the in-band (command-injection-echo) "+
					"or out-of-band (command-injection-oast) modules where possible.",
				ip.Name(), timeRounds, tmpl.Label, last.noSleep.Milliseconds(),
				sleepLow, last.low.Milliseconds(), sleepHigh, last.high.Milliseconds()),
			// Impact is Critical, but the oracle is timing-only and network-sensitive,
			// so the finding is reported as Tentative pending corroboration.
			Severity:   severity.Critical,
			Confidence: severity.Tentative,
		},
		// Per-round timings live in ExtractedResults (every round) and the
		// Description (final round); Metadata carries only the scan configuration.
		Metadata: map[string]any{
			"threshold_ms":        threshold.Milliseconds(),
			"confirmation_rounds": timeRounds,
			"sleep_high_s":        sleepHigh,
			"sleep_low_s":         sleepLow,
		},
	}, nil
}

// timedResult is one timed probe: its wall-clock latency plus, when capture is
// requested, the raw request/response so a confirmed finding can carry the
// actual proof pair as evidence instead of discarding it.
type timedResult struct {
	elapsed  time.Duration
	request  string
	response string
}

// sendTimedPayload sends a payload and returns its elapsed wall-clock duration.
// When capture is true it also records the raw request and full response so the
// caller can attach them to a finding (callers that only need the timing pass
// false to avoid reading the body on the hot path).
//
// NoClustering ensures byte-identical sleep probes are actually re-executed (a
// cached response would read as instant and defeat the timing measurement).
func (m *Module) sendTimedPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
	capture bool,
) (timedResult, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return timedResult{}, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	elapsed := time.Since(start)
	if err != nil {
		return timedResult{}, err
	}

	res := timedResult{elapsed: elapsed}
	if capture {
		res.request = string(fuzzedRaw)
		res.response = resp.FullResponseString()
	}
	resp.Close()

	return res, nil
}
