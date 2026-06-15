package sqli_time_blind

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
	// baselineSamples is how many unmodified requests are sent per insertion
	// point to model the target's normal response-time distribution before any
	// sleep payload is tested.
	baselineSamples = 4
	// timeStdevCoeff multiplies the baseline standard deviation when deriving
	// the delay threshold. sqlmap uses 7 (≈99.9999% confidence); 5 keeps us
	// sensitive while staying clear of normal network/server jitter.
	timeStdevCoeff = 5
	// minSleepMargin is the minimum absolute delay above the baseline mean that
	// a sleep payload must add before it is believed (guards low-variance hosts).
	minSleepMargin = 3 * time.Second
	// absoluteFloor is a hard lower bound on the threshold so a near-instant
	// baseline can never let trivial jitter masquerade as an injection.
	absoluteFloor = 2 * time.Second
	// maxThreshold caps the derived threshold: if a host is so slow/jittery that
	// the threshold would exceed this, the (10s) sleep payloads can't clear it,
	// so we skip rather than risk a false positive on an unstable target.
	maxThreshold = 9 * time.Second
)

// Module implements the time-based blind SQL injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new time-based blind SQL injection module.
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
		rhm: dedup.LazyDefaultRHM("sqli_time_blind"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests all insertion points for time-based blind SQL injection.
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

	// Create all insertion points (uses cached provider when available)
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	// Filter out already checked insertion points
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

ipScan:
	for _, ip := range points {
		baseValue := ip.BaseValue()

		// Model the target's normal latency for this insertion point and derive
		// a per-target delay threshold, instead of a single fixed cutoff. This
		// makes detection adaptive: fast targets can be confirmed with a modest
		// margin, while slow/jittery targets raise the bar (or are skipped).
		threshold, err := m.deriveThreshold(ctx, httpClient, ip)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			// errBaselineBlocked or a sampling error — either way this insertion
			// point has no reliable timing oracle, so move to the next one.
			continue
		}
		if threshold > maxThreshold {
			continue // Target too slow/jittery to time-test reliably
		}

		payloads := prioritizeByDBMS(getPayloadsForValue(baseValue), scanCtx, urlx.Host)

		for _, pair := range payloads {
			result, err := m.confirmTiming(ctx, httpClient, ip, pair, baseValue, threshold)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			if result != nil {
				result.URL = urlx.String()
				results = append(results, result)
				continue ipScan
			}
		}
	}

	return results, nil
}

// errBaselineBlocked signals that the insertion point's unmodified baseline is a
// WAF/CDN edge block, auth gate, or rate-limit response rather than an
// application response. Timing such a surface is meaningless (the request never
// reaches a backend query), so the caller skips the insertion point. It is not a
// host error — the host is up, it is just denying this request.
var errBaselineBlocked = errors.New("sqli_time_blind: baseline response is blocked")

// deriveThreshold samples the insertion point's unmodified latency a few times
// and returns the delay a sleep payload must exceed to be believed:
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
		// If even the unmodified request is blocked (CloudFront/WAF 403, 429
		// rate-limit, auth gate), there is no application surface to time-test —
		// skip rather than spend a probe per payload only to drop each one.
		if d.blocked {
			return 0, errBaselineBlocked
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

const (
	// sleepHigh / sleepLow are the two requested sleep durations used to prove
	// the response delay scales with the injected sleep value.
	sleepHigh = 6
	sleepLow  = 2
	// timeRounds is how many independent confirmation rounds must all pass.
	timeRounds = 2
)

// confirmTiming confirms a time-based blind SQLi across multiple rounds and
// verifies the observed delay tracks the requested sleep duration. The scaling
// factor is the decisive false-positive killer: random server slowness or a
// fixed-timeout/retry sink does not produce a delay that grows linearly with
// the SLEEP argument.
//
// Per round:
//   - the no-sleep payload must stay under the threshold (else the host is just slow);
//   - the high-sleep payload must exceed the threshold;
//   - the low-sleep payload must itself add a partial delay AND the high−low
//     differential must track the requested (high−low) seconds.
func (m *Module) confirmTiming(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	pair timePair,
	baseValue string,
	threshold time.Duration,
) (*output.ResultEvent, error) {
	render := func(seconds int) string { return baseValue + pair.render(seconds) }

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
		// A WAF/CDN block, auth gate, or rate-limit response is never a reliable
		// timing oracle: the request never reaches a backend query, and a 429/503
		// in particular injects its own latency that masquerades as a SQL sleep
		// (the motivating false positive: a CloudFront 403 on an X-Forwarded-For
		// payload whose round-trip jitter looked like a scaling delay). If any
		// probe in the round is blocked, the round proves nothing — drop it.
		if noSleep.blocked {
			return nil, nil
		}
		if noSleep.elapsed >= threshold {
			return nil, nil // Host is uniformly slow — not a reliable signal
		}

		high, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepHigh), capture)
		if err != nil {
			return nil, err
		}
		if high.blocked {
			return nil, nil // The slow response is the edge denying us, not SQL
		}
		if high.elapsed < threshold {
			return nil, nil // No delay from the high sleep payload
		}

		low, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepLow), false)
		if err != nil {
			return nil, err
		}
		if low.blocked {
			return nil, nil
		}
		// The low sleep must itself add a partial delay (rules out a one-off
		// spike on the high request)...
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

	// All rounds passed — confirmed time-based blind SQLi. Carry the differential
	// that proves it: the slow high-sleep probe is the primary pair, with the
	// unmodified baseline and the fast no-sleep control attached as evidence.
	// proof/control are always populated here: the final round captures, and the
	// loop only reaches this point once every round has passed.
	sleepPayload := render(sleepHigh)

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (unmodified request)", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
	ev.Add("control: no-sleep payload returned fast", control.request, control.response)

	extracted := []string{sleepPayload, render(0), pair.dbType}
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
		Info: output.Info{
			Description: fmt.Sprintf(
				"Time-based blind SQL injection confirmed over %d rounds; the response delay scales with "+
					"the injected sleep duration (final round: no-sleep %dms, %ds-sleep %dms, %ds-sleep %dms). "+
					"Database type: %s",
				timeRounds, last.noSleep.Milliseconds(), sleepLow, last.low.Milliseconds(),
				sleepHigh, last.high.Milliseconds(), pair.dbType),
			// Time-based blind is the least reliable SQLi confirmation: the only
			// signal is wall-clock latency, which network/edge jitter can forge.
			// Report it as a lead to verify by hand (Suspect/Tentative), not a
			// firmly-confirmed High.
			Severity:   severity.Suspect,
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

// timedResult is one timed probe: its wall-clock latency, whether the response
// was a WAF/CDN/auth/rate-limit block (so timing it proves nothing), plus, when
// capture is requested, the raw request/response so a confirmed finding can
// carry the actual proof pair as evidence instead of discarding it.
type timedResult struct {
	elapsed  time.Duration
	blocked  bool
	request  string
	response string
}

// sendTimedPayload sends a payload and returns its elapsed wall-clock duration.
// When capture is true it also records the raw request and full response so the
// caller can attach them to a finding (callers that only need the timing pass
// false to avoid reading the body on the hot path).
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
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	elapsed := time.Since(start)
	if err != nil {
		return timedResult{}, err
	}

	// Classify the response while it is still open: a 401/403/429/503 or a
	// WAF/CDN challenge means the request was denied, not processed by a backend
	// query, so its latency must never be read as a SQL sleep.
	res := timedResult{elapsed: elapsed, blocked: infra.IsBlockedResponse(resp)}
	if capture {
		res.request = string(fuzzedRaw)
		res.response = resp.FullResponseString()
	}
	resp.Close()

	return res, nil
}
