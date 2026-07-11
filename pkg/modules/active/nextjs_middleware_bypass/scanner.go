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

		result, err := m.executeAndCheck(modifiedRaw, ctx, httpClient, scanCtx, statusCode, hp.desc, hp.name+": "+hp.value, false)
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

		// checkCatchAll=true: a path rewrite can land on a generic 200 app shell
		// (home / marketing / a [...slug] catch-all) that is not the protected
		// resource. The header phase keeps the same path, so its still-denied
		// recheck already rules that out; the path phase needs an explicit
		// catch-all control.
		result, err := m.executeAndCheck(modifiedRaw, ctx, httpClient, scanCtx, statusCode, pp.desc, modifiedPath, true)
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
	scanCtx *modkit.ScanContext,
	origStatus int,
	desc string,
	payload string,
	checkCatchAll bool,
) (*output.ResultEvent, error) {
	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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

	// Catch-all control (path phase only): a rewritten path may resolve to a
	// generic 200 app shell served for any unmatched route. If the bypass body is
	// indistinguishable from the host's response to a random nonexistent path, the
	// rewrite reached the catch-all shell, not the protected resource — not a
	// middleware bypass.
	if checkCatchAll && !m.bypassDistinctFromCatchAll(ctx, httpClient, scanCtx, body) {
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

// bypassDistinctFromCatchAll reports whether the bypass body is a distinct
// protected resource rather than the host's catch-all app shell. A Next.js app
// that serves a generic 200 shell (home / marketing / a [...slug] catch-all) for
// unmatched routes answers a rewritten path with that shell rather than the
// protected resource, so a bypass body similar to the shell is not a real
// middleware bypass.
//
// The shell is sampled from THREE INDEPENDENT controls, OR-ed, so no single
// WAF/CDN-throttled probe can disable the guard — the failure mode that would let
// a wildcard-SPA shell be reported as a Critical bypass (a lone control throttled
// to a non-200 previously fell through to "distinct → keep"):
//   - a random nonexistent path via the clean original template (preserves the
//     request's auth headers),
//   - a random nonexistent web-root directory (RandomDirCatchAll), and
//   - the site root "/" (RootPageCatchAll).
//
// Each control fails OPEN (a non-200 / errored control is treated as "not the
// shell"), so a genuine bypass — where these controls are real 404s and the
// homepage is a distinct page — is never suppressed. Returns true (distinct →
// keep the finding) only when the bypass body matches NONE of the shell samples.
// ResemblesObservedPage is deliberately NOT used here: the observed page is the
// original 401/403 body, not the 200 shell, so it can never match the bypass.
func (m *Module) bypassDistinctFromCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	bypassBody string,
) bool {
	bypassSig := modkit.BodySignature(bypassBody)
	shellMatch := func(b string) bool { return modkit.BodiesSimilarSig(bypassSig, b) }

	// Control 1: a random nonexistent path via the clean original request
	// template (keeps the method and auth headers the protected request carried).
	if raw, err := httpmsg.SetPath(ctx.Request().Raw(), "/"+modkit.FreshCanary()+"-vgo404"); err == nil {
		if status, body, _, ok := m.freshProbe(ctx, httpClient, raw); ok && status == 200 && shellMatch(body) {
			return false // matches the catch-all shell → not a bypass
		}
	}

	// Controls 2 & 3: independent web-root directory and site-root shell samples.
	// Distinct (keep) only when the bypass body matches neither.
	return !modkit.RandomDirCatchAll(scanCtx, ctx, httpClient, shellMatch) &&
		!modkit.RootPageCatchAll(scanCtx, ctx, httpClient, shellMatch)
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
	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
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
