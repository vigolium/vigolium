package nextjs_middleware_bypass

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements the Next.js middleware bypass active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
}

// New creates a new Next.js Middleware Bypass module.
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
		ds:                dedup.LazyDiskSet("nextjs_middleware_bypass"),
		limitCheckPerHost: 20,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests 401/403 Next.js pages for middleware bypass.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	statusCode := ctx.Response().StatusCode()
	if statusCode != 401 && statusCode != 403 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	// Check if this is a Next.js host
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}

	// Dedup with per-host limit
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil {
		_, shouldContinue := diskSet.IncrementAndCheck(urlx.Hostname(), m.limitCheckPerHost)
		if !shouldContinue {
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	// Phase 1: Header-based bypass probes (CVE-2025-29927)
	for _, hp := range headerPayloads {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), hp.name, hp.value)
		if err != nil {
			continue
		}

		result, err := m.executeAndCheck(modifiedRaw, ctx, httpClient, statusCode, hp.desc, hp.name+": "+hp.value)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	// Phase 2: Path-based bypass probes
	path := urlx.EscapedPath()
	for _, pp := range pathPayloads {
		modifiedPath := pp.transform(path)
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), modifiedPath)
		if err != nil {
			continue
		}

		result, err := m.executeAndCheck(modifiedRaw, ctx, httpClient, statusCode, pp.desc, modifiedPath)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	return results, nil
}

// executeAndCheck sends the modified request and checks for a bypass.
func (m *Module) executeAndCheck(
	modifiedRaw []byte,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	origStatus int,
	desc string,
	payload string,
) (*output.ResultEvent, error) {
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil, nil
	}

	// Validate it's not a login page or 404
	body := resp.Body().String()
	bodyLower := strings.ToLower(body)
	if isLoginOrErrorPage(bodyLower) {
		return nil, nil
	}

	// Capture the bypass (attack) response before it is consumed/closed by the
	// confirmation rounds below; it stays the finding's primary Response.
	attackResp := resp.FullResponseString()

	// Each finding gets its own evidence collector. Record the ORIGINAL,
	// pre-bypass 401/403 pair (the baseline that proves middleware enforcement
	// was in place) and let confirmBypass append the reproduction rounds.
	ev := modkit.NewEvidenceCollector()
	if origReq := ctx.Request(); origReq != nil {
		var origRespStr string
		if origResp := ctx.Response(); origResp != nil {
			origRespStr = string(origResp.Raw())
		}
		ev.Add(fmt.Sprintf("original-%d", origStatus), string(origReq.Raw()), origRespStr)
	}

	// Confirm the bypass is real and reproducible, not a transient flap: the
	// captured 401/403 is a crawl-time snapshot that may have been a momentary
	// rate-limit/WAF block (or the endpoint may simply return 200 for everything
	// now). Re-verify with the bypass payload as the only variable.
	if !m.confirmBypass(ctx, httpClient, modifiedRaw, ev) {
		return nil, nil
	}

	target := ctx.Target()
	return &output.ResultEvent{
		ModuleID:           ModuleID,
		URL:                target,
		Matched:            target,
		Request:            string(modifiedRaw),
		Response:           attackResp,
		AdditionalEvidence: ev.Entries(),
		ExtractedResults: []string{
			fmt.Sprintf("Bypass: %s", desc),
			fmt.Sprintf("Payload: %s", payload),
			fmt.Sprintf("Original status: %d → 200", origStatus),
		},
		Info: output.Info{
			Name:        "Next.js Middleware Bypass",
			Description: fmt.Sprintf("Next.js middleware authentication bypass via %s. Original response was %d, bypassed to 200.", desc, origStatus),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"nextjs", "middleware", "auth-bypass", "cve-2025-29927"},
			Reference:   []string{"https://github.com/advisories/GHSA-f82v-jwr5-mffw"},
		},
	}, nil
}

// confirmBypass re-runs the pair interleaved, with the bypass payload as the only
// variable, to rule out a transient flap or a host that simply 200s everything:
// each round the ORIGINAL (unmodified) request must STILL be denied (401/403) and
// the bypass request must STILL return a non-login/non-error 200. The fetches
// bypass the response cache so a stale replay can't mask instability. Fails
// closed (drops) on a fetch error — a CVE-class claim should not rest on an
// unverifiable transition.
func (m *Module) confirmBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	modifiedRaw []byte,
	ev *modkit.EvidenceCollector,
) bool {
	const rounds = 2
	origRaw := ctx.Request().Raw()
	for round := 1; round <= rounds; round++ {
		status, _, fullResp, ok := m.freshProbe(ctx, httpClient, origRaw)
		if !ok || (status != 401 && status != 403) {
			return false // original request not denied → the 401/403 wasn't stable
		}
		ev.Add(fmt.Sprintf("confirm round %d (original denied)", round), string(origRaw), fullResp)

		status, body, fullResp, ok := m.freshProbe(ctx, httpClient, modifiedRaw)
		if !ok || status != 200 || isLoginOrErrorPage(strings.ToLower(body)) {
			return false // bypass not reproducibly allowed with real content
		}
		ev.Add(fmt.Sprintf("confirm round %d (bypass allowed)", round), string(modifiedRaw), fullResp)
	}
	return true
}

// freshProbe issues raw with redirects disabled and the response cache bypassed,
// returning the status, body, and full raw response string. The full response is
// captured before Close so callers can record it as confirmation evidence. ok is
// false on parse/transport error or nil response.
func (m *Module) freshProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	raw []byte,
) (int, string, string, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", "", false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return 0, "", "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), resp.FullResponseString(), true
}

// isLoginOrErrorPage checks if the body looks like a login or error page.
func isLoginOrErrorPage(bodyLower string) bool {
	// Check shared enforcement and login redirect patterns
	if authzutil.ContainsEnforcementString(bodyLower) {
		return true
	}
	for _, pattern := range authzutil.LoginRedirectPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	// Additional login indicators not covered by authzutil
	if strings.Contains(bodyLower, "sign in") || strings.Contains(bodyLower, "log in") {
		return true
	}

	// Check for generic 404 content
	if strings.Contains(bodyLower, "page not found") || strings.Contains(bodyLower, "404") {
		return true
	}

	return false
}
