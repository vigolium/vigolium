package nextjs_data_leakage

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// catchAllProbeSlug is an improbable path segment used to detect a data route
// that answers EVERY path with a 200 pageProps body (a CDN/error-boundary
// catch-all) rather than selectively serving the requested page's data.
const catchAllProbeSlug = "vigolium-nonexistent-probe-9f3a2c7e"

// Module implements the Next.js data route leakage active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Data Route Leakage module.
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
		ds: dedup.LazyDiskSet("nextjs_data_leakage"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests auth-protected Next.js pages for data route leakage.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	// Only check genuinely auth-protected responses. A 401/403 is an unambiguous
	// authorization denial. A 302, however, is NOT necessarily auth: locale,
	// trailing-slash, www/apex and canonical redirects are all 302, and EVERY
	// public Next.js page's data route returns 200 JSON with pageProps by design.
	// Treating a non-auth 302 as "protected" flags ordinary public pages as data
	// leaks, so a 302 only counts when it redirects to a login/auth page.
	statusCode := ctx.Response().StatusCode()
	switch statusCode {
	case 401, 403:
		// Unambiguous authorization denial — proceed.
	case 302:
		if !authzutil.IsLoginRedirect(statusCode, ctx.Response().Header("Location")) {
			return nil, nil
		}
	default:
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	// Check if this is a Next.js host
	body := ctx.Response().BodyToString()
	if !jsframework.LooksLikeNextJS(host, body) {
		return nil, nil
	}

	// Get buildId
	buildID := jsframework.GetBuildID(host)
	if buildID == "" {
		// Fallback: extract from current page body
		if m := jsframework.BuildIDRegex.FindStringSubmatch(body); len(m) > 1 {
			buildID = m[1]
		}
	}
	if buildID == "" {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Build data URL: /_next/data/<buildId>/<path>.json
	path := strings.TrimPrefix(urlx.Path, "/")
	if path == "" {
		path = "index"
	}
	dataPath := fmt.Sprintf("/_next/data/%s/%s.json", buildID, path)

	// Build and send the data route request
	modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), dataPath)
	if err != nil {
		return nil, nil
	}

	// Strip auth headers from the request to test unauthorized access
	modifiedRaw, _ = httpmsg.RemoveHeader(modifiedRaw, "Cookie")
	modifiedRaw, _ = httpmsg.RemoveHeader(modifiedRaw, "Authorization")

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil, nil
	}

	respBody := resp.Body().String()

	// Validate: must be JSON carrying real protected-page data, not a notFound stub
	// or a data-layer auth redirect (Next.js emits __N_REDIRECT when
	// getServerSideProps returns a redirect — that means the data route enforces
	// auth too, so nothing leaked).
	respCT := resp.Response().Header.Get("Content-Type")
	if !strings.Contains(respCT, "application/json") {
		return nil, nil
	}
	if !isLeakBody(respBody) {
		return nil, nil
	}

	// Confirm the leak before reporting: it must REPRODUCE on a fresh unauth
	// re-fetch (not a one-off 200 from a cache/edge flap), and the data route must
	// not be a blind 200-everything catch-all (a CDN or error boundary that answers
	// every path with the same pageProps body). Either gate failing means the route
	// responds the same with or without a real path — not an auth leak.
	if !m.confirmDataRouteLeak(ctx, httpClient, dataPath, buildID) {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.Scheme + "://" + host + dataPath,
			Request:  string(modifiedRaw),
			Response: resp.FullResponseString(),
			ExtractedResults: []string{
				fmt.Sprintf("Data route: %s", dataPath),
				fmt.Sprintf("BuildID: %s", buildID),
				fmt.Sprintf("Original status: %d", statusCode),
			},
			Info: output.Info{
				Name:        "Next.js Data Route Leakage",
				Description: fmt.Sprintf("Auth-protected page %s leaks data via Next.js data route %s (original status: %d, data route: 200)", urlx.Path, dataPath, statusCode),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"nextjs", "data-leakage", "authorization"},
				Reference:   []string{"https://nextjs.org/docs/pages/building-your-application/data-fetching"},
			},
		},
	}, nil
}

// isLeakBody reports whether a data-route body carries real protected-page data
// worth flagging: it must contain pageProps and must NOT be a Next.js notFound
// payload or a __N_REDIRECT (data-layer auth redirect) response.
func isLeakBody(body string) bool {
	if !strings.Contains(body, "pageProps") {
		return false
	}
	if strings.Contains(body, `"notFound":true`) || strings.Contains(body, `"notFound": true`) {
		return false
	}
	if strings.Contains(body, "__N_REDIRECT") {
		return false
	}
	return true
}

// fetchUnauthDataRouteBody issues an unauthenticated GET (Cookie/Authorization
// stripped, no redirects) for a data path and returns its body when the response
// is a 200 application/json. NoClustering bypasses the response cache so each call
// is a genuinely fresh observation. ok is false on any transport/parse error or a
// non-200 / non-JSON response.
func (m *Module) fetchUnauthDataRouteBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	dataPath string,
) (string, bool) {
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), dataPath)
	if err != nil {
		return "", false
	}
	raw, _ = httpmsg.RemoveHeader(raw, "Cookie")
	raw, _ = httpmsg.RemoveHeader(raw, "Authorization")

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return "", false
	}
	defer resp.Close()
	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return "", false
	}
	if !strings.Contains(resp.Response().Header.Get("Content-Type"), "application/json") {
		return "", false
	}
	return resp.Body().String(), true
}

// confirmDataRouteLeak validates a candidate leak with two fresh requests.
//  1. Reproduce: the unauth data route must STILL return a 200 pageProps body — a
//     transient/cached 200 that does not recur is dropped (fails closed).
//  2. Catch-all guard: an improbable data path under the same buildId must NOT
//     return a similar 200 pageProps body; a route that does answers every path the
//     same way (CDN / error boundary), so the target's 200 is not an auth bypass.
//     The catch-all probe fails OPEN — a transient error on it never suppresses a
//     reproduced leak.
func (m *Module) confirmDataRouteLeak(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	dataPath, buildID string,
) bool {
	body, ok := m.fetchUnauthDataRouteBody(ctx, httpClient, dataPath)
	if !ok || !isLeakBody(body) {
		return false
	}

	decoyPath := fmt.Sprintf("/_next/data/%s/%s.json", buildID, catchAllProbeSlug)
	if decoy, ok := m.fetchUnauthDataRouteBody(ctx, httpClient, decoyPath); ok && isLeakBody(decoy) &&
		modkit.RatioSimilar(
			modkit.NewResponseSignature(200, body, ""),
			modkit.NewResponseSignature(200, decoy, ""),
		) {
		return false
	}
	return true
}
