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
		d, err := m.sendTimedPayload(ctx, httpClient, ip, base)
		if err != nil {
			return 0, err
		}
		samples = append(samples, d)
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
		// The low sleep must itself add a partial delay (rules out a one-off spike
		// on the high request)...
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

	// All rounds passed — confirmed delay-scaling command injection.
	sleepPayload := render(sleepHigh)
	fuzzedRaw := ip.BuildRequest([]byte(sleepPayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{sleepPayload, render(0), tmpl.Label},
		MatcherStatus:    true,
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf(
				"Possible time-based blind OS command injection in parameter %q: the response delay "+
					"scaled with the injected sleep duration above an adaptive per-target threshold "+
					"across %d independent rounds via the %s payload. Detection is purely timing-based "+
					"and can still be influenced by network conditions — corroborate with the in-band "+
					"(command-injection-echo) or out-of-band (command-injection-oast) modules where possible.",
				ip.Name(), timeRounds, tmpl.Label),
			// Impact is Critical, but the oracle is timing-only and network-sensitive,
			// so the finding is reported as Tentative pending corroboration.
			Severity:   severity.Critical,
			Confidence: severity.Tentative,
		},
	}, nil
}

// sendTimedPayload sends a payload and returns the elapsed wall-clock duration.
// NoClustering ensures byte-identical sleep probes are actually re-executed (a
// cached response would read as instant and defeat the timing measurement).
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
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	elapsed := time.Since(start)
	if err != nil {
		return 0, err
	}
	resp.Close()
	return elapsed, nil
}
