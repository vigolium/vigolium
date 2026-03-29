package sqli_time_blind

import (
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

// sleepThreshold is the minimum response time differential to consider
// a timing-based injection confirmed. Set high (8s) to avoid false positives
// from slow servers or network jitter.
const sleepThreshold = 8 * time.Second

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

		payloads := getPayloadsForValue(baseValue)

		for _, pair := range payloads {
			sleepPayload := baseValue + pair.sleepVal
			noSleepPayload := baseValue + pair.noSleep

			result, err := m.testTimingPair(ctx, httpClient, ip, sleepPayload, noSleepPayload, pair.dbType)
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

// testTimingPair implements the triple verification algorithm: sleep → no-sleep → sleep.
func (m *Module) testTimingPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	sleepPayload, noSleepPayload, dbType string,
) (*output.ResultEvent, error) {
	// Step 1: Send sleep payload (should be slow)
	elapsed1, err := m.sendTimedPayload(ctx, httpClient, ip, sleepPayload)
	if err != nil {
		return nil, err
	}
	if elapsed1 < sleepThreshold {
		return nil, nil // No delay observed
	}

	// Step 2: Send no-sleep payload (should be fast)
	elapsedNoSleep, err := m.sendTimedPayload(ctx, httpClient, ip, noSleepPayload)
	if err != nil {
		return nil, err
	}
	if elapsedNoSleep >= sleepThreshold {
		return nil, nil // Server is just slow, not injectable
	}

	// Step 3: Send sleep payload again (should be slow again)
	elapsed2, err := m.sendTimedPayload(ctx, httpClient, ip, sleepPayload)
	if err != nil {
		return nil, err
	}
	if elapsed2 < sleepThreshold {
		return nil, nil // Inconsistent — likely false positive
	}

	// All checks passed — confirmed time-based blind SQLi
	fuzzedRaw := ip.BuildRequest([]byte(sleepPayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{sleepPayload, noSleepPayload, dbType},
		Info: output.Info{
			Description: "Time-based blind SQL injection confirmed via triple verification " +
				"(sleep/no-sleep/sleep). Database type: " + dbType,
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
