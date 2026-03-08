package ssti_blind

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

// timeThreshold is the minimum response time differential to consider
// a time-delay injection confirmed.
const timeThreshold = 2 * time.Second

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
			// Time-delay findings get Tentative confidence (lower than OAST)
			result.Info.Confidence = severity.Tentative
			results = append(results, result)
			return results, nil
		}
	}

	return results, nil
}

// testTimingPair implements triple verification: slow → fast → slow.
func (m *Module) testTimingPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	slowPayload, fastPayload, engine string,
) (*output.ResultEvent, error) {
	// Step 1: Send slow payload (should cause delay)
	elapsed1, err := m.sendTimedPayload(ctx, httpClient, ip, slowPayload)
	if err != nil {
		return nil, err
	}
	if elapsed1 < timeThreshold {
		return nil, nil
	}

	// Step 2: Send fast payload (should be quick)
	elapsedFast, err := m.sendTimedPayload(ctx, httpClient, ip, fastPayload)
	if err != nil {
		return nil, err
	}
	if elapsedFast >= timeThreshold {
		return nil, nil // Server is just slow
	}

	// Step 3: Send slow payload again (should cause delay again)
	elapsed2, err := m.sendTimedPayload(ctx, httpClient, ip, slowPayload)
	if err != nil {
		return nil, err
	}
	if elapsed2 < timeThreshold {
		return nil, nil // Inconsistent
	}

	// All checks passed — confirmed blind SSTI via time delay
	fuzzedRaw := ip.BuildRequest([]byte(slowPayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{slowPayload, fastPayload, engine},
		Info: output.Info{
			Description: fmt.Sprintf(
				"Blind SSTI detected via time-delay in %s template engine. "+
					"Slow payload caused consistent delay while fast payload responded quickly.",
				engine,
			),
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
