package ssti_blind

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Time-delay detection tuning.
//
// Blind SSTI via wall-clock timing is inherently noisy: a slow backend, GC
// pause, or unrelated network jitter can produce multi-second responses on
// non-vulnerable endpoints. The constants below are picked to make false
// positives unlikely at the cost of a few extra HTTP requests:
//
//   - slowMinDuration: a "slow" probe must take at least this long to count.
//     Bumped well above typical jitter (5xx errors, slow DBs).
//   - fastMaxDuration: a "fast" probe must complete under this; otherwise
//     we conclude the server is just slow and bail.
//   - minSeparation:   the slowest slow-probe must beat the fastest baseline
//     by this much. Catches the "server is consistently slow" case where
//     both slow and fast cross slowMinDuration but the payload didn't help.
//   - confirmSlowRounds / confirmFastRounds: how many probes of each kind
//     to send before declaring a hit. Pattern is interleaved
//     slow-fast-slow-fast-slow so any background load spike shows up as a
//     fast-probe outlier and aborts the check.
const (
	slowMinDuration   = 6 * time.Second
	fastMaxDuration   = 3 * time.Second
	minSeparation     = 3 * time.Second
	confirmSlowRounds = 3
	confirmFastRounds = 2
)

// Module implements the blind SSTI active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new blind SSTI module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("ssti_blind"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for blind SSTI.
// It tries OAST callbacks first, then falls back to time-delay detection.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Check deduplication
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Phase 1: Try OAST-based detection (Firm confidence, async results)
	oast := scanCtx.OASTProv()
	if oast != nil && oast.Enabled() {
		requestHash := ctx.Request().ID()

		for _, p := range oastPayloads {
			oastURL := oast.GenerateURL(urlx.String(), ip.Name(), "parameter", ModuleID, requestHash)
			if oastURL == "" {
				continue
			}

			payload := fmt.Sprintf(p.template, oastURL)
			fuzzedRaw := ip.BuildRequest([]byte(payload))

			fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
			if err != nil {
				continue
			}
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return nil, nil
				}
				continue
			}
			resp.Close()
		}
		// OAST results arrive asynchronously via polling callbacks
	}

	// Phase 2: Time-delay fallback (Tentative confidence)
	var results []*output.ResultEvent

	for _, p := range timePayloads {
		result, err := m.testTimingPair(ctx, httpClient, ip, p.slowExpr, p.fastExpr, p.engine)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil {
			result.URL = urlx.String()
			// Time-delay findings are prone to backend-delay false positives, so
			// (unlike the OAST path) they are downgraded to suspect/tentative.
			result.Info.Severity = severity.Suspect
			result.Info.Confidence = severity.Tentative
			results = append(results, result)
			return results, nil
		}
	}

	return results, nil
}

// testTimingPair confirms a blind SSTI via interleaved slow/fast probes.
//
// Pattern (worst case): slow → fast → slow → fast → slow.
// Early exits keep the cost low for non-vulnerable endpoints:
//   - First slow under slowMinDuration → bail after 1 request.
//   - Any baseline (fast) probe over fastMaxDuration → bail (server is slow).
//   - Any subsequent slow under slowMinDuration → bail (inconsistent).
//
// Final decision requires ALL slow probes ≥ slowMinDuration AND
// min(slow) − max(fast) ≥ minSeparation, so a uniformly slow backend
// can't trigger a false positive.
func (m *Module) testTimingPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	slowPayload, fastPayload, engine string,
) (*output.ResultEvent, error) {
	slowTimes := make([]time.Duration, 0, confirmSlowRounds)
	fastTimes := make([]time.Duration, 0, confirmFastRounds)

	for i := 0; i < confirmSlowRounds; i++ {
		elapsed, err := m.sendTimedPayload(ctx, httpClient, ip, slowPayload)
		if err != nil {
			return nil, err
		}
		if elapsed < slowMinDuration {
			return nil, nil
		}
		slowTimes = append(slowTimes, elapsed)

		// Interleave a baseline probe between slow probes (not after the last).
		if i < confirmFastRounds {
			fastElapsed, err := m.sendTimedPayload(ctx, httpClient, ip, fastPayload)
			if err != nil {
				return nil, err
			}
			if fastElapsed >= fastMaxDuration {
				return nil, nil // Server is just slow today.
			}
			fastTimes = append(fastTimes, fastElapsed)
		}
	}

	// Statistical separation: the slowest slow must beat the fastest baseline
	// by at least minSeparation. Catches drift where everything got slower
	// without the payload actually doing anything.
	slowMin := minDuration(slowTimes)
	fastMax := maxDuration(fastTimes)
	if slowMin-fastMax < minSeparation {
		return nil, nil
	}

	fuzzedRaw := ip.BuildRequest([]byte(slowPayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{slowPayload, fastPayload, engine},
		Info: output.Info{
			Description: fmt.Sprintf(
				"Blind SSTI detected via time-delay in %s template engine. "+
					"Slow payload caused consistent delay across %d probes "+
					"(min=%v) while %d baseline probes stayed fast (max=%v).",
				engine, len(slowTimes), slowMin.Round(time.Millisecond),
				len(fastTimes), fastMax.Round(time.Millisecond),
			),
		},
	}, nil
}

// minDuration returns the smallest duration in d. Empty slice → 0.
func minDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	m := d[0]
	for _, x := range d[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

// maxDuration returns the largest duration in d. Empty slice → 0.
func maxDuration(d []time.Duration) time.Duration {
	var m time.Duration
	for _, x := range d {
		if x > m {
			m = x
		}
	}
	return m
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
