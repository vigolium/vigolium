package sqli_time_blind

import (
	"fmt"
	"math"
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
		d, err := m.sendTimedPayload(ctx, httpClient, ip, base)
		if err != nil {
			return 0, err
		}
		samples = append(samples, d)
	}

	mean, stdev := meanStdev(samples)
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

// meanStdev computes the mean and (population) standard deviation of durations.
func meanStdev(samples []time.Duration) (mean, stdev time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	m := sum / float64(len(samples))
	var variance float64
	for _, s := range samples {
		d := float64(s) - m
		variance += d * d
	}
	variance /= float64(len(samples))
	return time.Duration(m), time.Duration(math.Sqrt(variance))
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

	for round := 0; round < timeRounds; round++ {
		noSleep, err := m.sendTimedPayload(ctx, httpClient, ip, render(0))
		if err != nil {
			return nil, err
		}
		if noSleep >= threshold {
			return nil, nil // Host is uniformly slow — not a reliable signal
		}

		high, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepHigh))
		if err != nil {
			return nil, err
		}
		if high < threshold {
			return nil, nil // No delay from the high sleep payload
		}

		low, err := m.sendTimedPayload(ctx, httpClient, ip, render(sleepLow))
		if err != nil {
			return nil, err
		}
		// The low sleep must itself add a partial delay (rules out a one-off
		// spike on the high request)...
		if low < time.Duration(sleepLow)*time.Second/2 {
			return nil, nil
		}
		// ...and the high−low differential must track the requested (high−low)
		// seconds (at least half, allowing for overhead/jitter).
		observed := high - low
		expected := time.Duration(sleepHigh-sleepLow) * time.Second
		if observed < expected/2 {
			return nil, nil
		}
	}

	// All rounds passed — confirmed time-based blind SQLi.
	sleepPayload := render(sleepHigh)
	fuzzedRaw := ip.BuildRequest([]byte(sleepPayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{sleepPayload, render(0), pair.dbType},
		Info: output.Info{
			Description: fmt.Sprintf(
				"Time-based blind SQL injection confirmed over %d rounds; the response delay "+
					"scales with the injected sleep duration. Database type: %s", timeRounds, pair.dbType),
			Severity:   severity.High,
			Confidence: severity.Firm,
		},
	}, nil
}

// sendTimedPayload sends a payload and returns the elapsed wall-clock duration.
func (m *Module) sendTimedPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (time.Duration, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return 0, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	elapsed := time.Since(start)

	if err != nil {
		return 0, err
	}
	resp.Close()

	return elapsed, nil
}
