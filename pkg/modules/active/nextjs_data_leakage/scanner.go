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

	// Validate: must be JSON with pageProps, not a notFound response
	respCT := resp.Response().Header.Get("Content-Type")
	if !strings.Contains(respCT, "application/json") {
		return nil, nil
	}
	if !strings.Contains(respBody, "pageProps") {
		return nil, nil
	}
	if strings.Contains(respBody, `"notFound":true`) || strings.Contains(respBody, `"notFound": true`) {
		return nil, nil
	}
	// A data route that itself returns a redirect payload is enforcing auth at the
	// data layer too — not leaking the protected page's data. Next.js emits
	// __N_REDIRECT when getServerSideProps returns a redirect.
	if strings.Contains(respBody, "__N_REDIRECT") {
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
