package server_side_js_injection

import (
	"fmt"
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// looksLikeNodeBackend reports whether the observed response indicates a server-side
// JavaScript (Node.js) stack. Server-side JS injection can only occur on a JS runtime,
// so gating here keeps the busy-wait timing payloads (and their CPU cost) off PHP /
// Java / Python / Ruby targets, and prevents a coincidentally-slow non-JS backend from
// ever reaching the timing oracle. The signal set is the shared jsframework predicate.
func looksLikeNodeBackend(ctx *httpmsg.HttpRequestResponse) bool {
	var host, xpb, server, body string
	if svc := ctx.Service(); svc != nil {
		host = svc.Host()
	}
	if resp := ctx.Response(); resp != nil {
		xpb, server, body = resp.Header("X-Powered-By"), resp.Header("Server"), resp.BodyToString()
	}
	return jsframework.LooksLikeServerSideJS(host, xpb, server, body)
}

// Time-delay tuning. Blind timing is inherently noisy (GC pauses, jitter, slow
// backends), so the thresholds below favour false-negative over false-positive and
// require the delay to be inducible and repeatable, not a single slow response.
//
//   - slowMinDuration: a "slow" busy-wait probe must take at least this long.
//   - fastMaxDuration: a "fast" (zero-duration) probe must complete under this;
//     otherwise the server is just slow and the check bails.
//   - minSeparation:   the slowest slow-probe must beat the fastest baseline by
//     this much, catching a uniformly-slow backend.
//   - confirm*Rounds:  interleaved slow/fast probes (slow-fast-slow-fast-slow).
const (
	slowMinDuration   = 6 * time.Second
	fastMaxDuration   = 3 * time.Second
	minSeparation     = 3 * time.Second
	confirmSlowRounds = 3
	confirmFastRounds = 2

	// Busy-wait milliseconds. The slow value must comfortably exceed slowMinDuration;
	// the fast value produces no loop at all (b-a < 0 is immediately false).
	slowBusyMs = 6500
	fastBusyMs = 0
)

// Module implements the server-side JavaScript injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new server-side JavaScript injection module.
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
		rhm: dedup.LazyDefaultRHM("server_side_js_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for server-side JavaScript
// injection: out-of-band callbacks first (Firm, async), then busy-wait timing.
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
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	// Tech-stack gate: only probe server-side JavaScript stacks.
	if !looksLikeNodeBackend(ctx) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	// Phase 1: OAST (Firm). Findings arrive asynchronously via the polling callback.
	if oast := scanCtx.OASTProv(); oast != nil && oast.Enabled() {
		requestHash := ctx.Request().ID()
		for _, tmpl := range oastPayloads {
			host := modkit.OASTURLFor(oast, oastclass.CMDI, urlx.String(), ip.Name(), "server-side-javascript command execution", ModuleID, requestHash)
			if host == "" {
				break
			}
			payload := fmt.Sprintf(tmpl, host)
			oast.RecordPayload(host, payload)
			req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())
			resp, _, execErr := httpClient.Execute(req, http.Options{})
			if execErr != nil {
				if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
					return nil, nil
				}
				continue
			}
			resp.Close()
		}
	}

	// Phase 2: busy-wait timing (Tentative — prone to backend-delay noise).
	var results []*output.ResultEvent
	for _, p := range timePayloads {
		result, err := m.testTiming(ctx, httpClient, ip, p)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if result != nil {
			result.URL = urlx.String()
			result.Info.Severity = severity.Suspect
			result.Info.Confidence = severity.Tentative
			results = append(results, result)
			return results, nil
		}
	}
	return results, nil
}

// testTiming confirms a busy-wait delay via interleaved slow/fast probes. It bails
// cheaply for non-vulnerable endpoints: the first non-slow slow-probe, or any
// baseline probe over fastMaxDuration, aborts after one request. A finding needs all
// slow probes ≥ slowMinDuration and min(slow) − max(fast) ≥ minSeparation, so a
// uniformly-slow backend cannot trigger it.
func (m *Module) testTiming(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	p jsTimePayload,
) (*output.ResultEvent, error) {
	slowPayload := p.render(slowBusyMs)
	fastPayload := p.render(fastBusyMs)

	slowTimes := make([]time.Duration, 0, confirmSlowRounds)
	fastTimes := make([]time.Duration, 0, confirmFastRounds)

	for i := 0; i < confirmSlowRounds; i++ {
		elapsed, err := m.sendTimed(ctx, httpClient, ip, slowPayload)
		if err != nil {
			return nil, err
		}
		if elapsed < slowMinDuration {
			return nil, nil
		}
		slowTimes = append(slowTimes, elapsed)

		if i < confirmFastRounds {
			fastElapsed, err := m.sendTimed(ctx, httpClient, ip, fastPayload)
			if err != nil {
				return nil, err
			}
			if fastElapsed >= fastMaxDuration {
				return nil, nil // server is just slow today
			}
			fastTimes = append(fastTimes, fastElapsed)
		}
	}

	// slowTimes and fastTimes are non-empty here (each loop iteration either appends
	// or returns early), so slices.Min/Max are safe.
	slowMin := slices.Min(slowTimes)
	fastMax := slices.Max(fastTimes)
	if slowMin-fastMax < minSeparation {
		return nil, nil
	}

	return &output.ResultEvent{
		Request:          string(ip.BuildRequest([]byte(slowPayload))),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{slowPayload, fastPayload, p.context},
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf(
				"Blind server-side JavaScript injection via busy-wait time-delay (%s context). The slow payload caused a consistent delay across %d probes (min=%v) while %d zero-duration probes stayed fast (max=%v).",
				p.context, len(slowTimes), slowMin.Round(time.Millisecond),
				len(fastTimes), fastMax.Round(time.Millisecond),
			),
		},
		Metadata: map[string]any{output.MetaSignal: output.SignalTiming},
	}, nil
}

// sendTimed sends one payload and returns the elapsed wall-clock. NoClustering makes
// every send a genuine round-trip so the request-cluster cache can't return a cached
// ~0ms copy of a re-sent slow probe (which would defeat the timing confirmation).
func (m *Module) sendTimed(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (time.Duration, error) {
	req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())
	// SendTimed: requester-measured latency, not the queue.
	resp, elapsed, err := modkit.SendTimed(httpClient, req, http.Options{})
	if err != nil {
		return 0, err
	}
	resp.Close()
	return elapsed, nil
}
