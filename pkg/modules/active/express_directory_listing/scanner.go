package express_directory_listing

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// probePath defines a directory path to check for listing exposure.
type probePath struct {
	path string
	name string
}

// probePaths is the list of common Express static/upload directories to test.
var probePaths = []probePath{
	{path: "/public/", name: "public"},
	{path: "/uploads/", name: "uploads"},
	{path: "/static/", name: "static"},
	{path: "/assets/", name: "assets"},
	{path: "/files/", name: "files"},
	{path: "/media/", name: "media"},
	{path: "/images/", name: "images"},
	{path: "/dist/", name: "dist"},
}

// Module implements the Express directory listing exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express Directory Listing module.
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
		ds: dedup.LazyDiskSet("express_directory_listing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerRequest probes for directory listing exposure per request.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Fingerprint 404 response body hash
	notFoundHash := get404Hash(ctx, httpClient)

	// Host-wide catch-all guard: if a random, guaranteed-nonexistent directory
	// already "lists", the host renders a directory-listing-shaped body for any
	// path (an SPA shell, a wildcard rewrite, a templated soft-404) and every
	// per-directory finding below is spurious.
	if modkit.RandomDirCatchAll(scanCtx, ctx, httpClient, isDirectoryListing) {
		return nil, nil
	}

	var results []*output.ResultEvent
	base := modkit.ServiceBaseURL(service)

	for _, probe := range probePaths {
		probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probe.path)
		if err != nil {
			continue
		}
		probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

		// probeRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

		resp, _, err := httpClient.Execute(probeReq, http.Options{})
		if err != nil {
			continue
		}

		if resp.Response() == nil {
			resp.Close()
			continue
		}

		statusCode := resp.Response().StatusCode

		// Must be 2xx
		if statusCode < 200 || statusCode >= 300 {
			resp.Close()
			continue
		}

		body := resp.Body().String()

		// Skip if body hash matches 404
		if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
			resp.Close()
			continue
		}

		// Catch-all / SPA shell guard: these probe paths are static-asset
		// directories (/public, /assets, /static, ...) — exactly where a catch-all
		// reverse proxy serves the application index shell. A probe whose body is
		// the observed page is that shell, not a listing.
		if modkit.ResemblesObservedPage(ctx, body) {
			resp.Close()
			continue
		}

		// Check for directory listing indicators
		if isDirectoryListing(body) {
			results = append(results, buildResult(base, host, probe, string(probeRaw), resp.FullResponseString()))
		}

		resp.Close()
	}

	return results, nil
}

// isDirectoryListing checks the response body for directory listing indicators.
//
// A genuine auto-generated listing (serve-index, Nginx autoindex, Apache
// autoindex) is a bare, machine-emitted index. The checks below therefore
// require an unmistakable autoindex signature — the "Index of" / "listing
// directory" phrase, or a parent-directory ("../") link inside a file table/pre
// block — and first reject application / CMS / single-page-app content pages,
// which routinely carry a heading, a table, and links yet are not listings.
func isDirectoryListing(body string) bool {
	lower := strings.ToLower(body)

	// Negative guard: a rendered application/CMS/SPA content page (e.g. a Gatsby,
	// Next.js, or React route) is never an auto-generated directory listing, even
	// though it commonly has an <h1>, a <table>, and <a href=> links. Framework,
	// SSG/CMS, and SEO/social markers are absent from every real autoindex, so
	// their presence rules a listing out.
	if modkit.LooksLikeAppPage(lower) {
		return false
	}

	// serve-index / Nginx / Apache autoindex name the directory with an unmistakable
	// phrase in BOTH the <title> and the <h1>. Requiring both — not the title alone —
	// is what separates a real autoindex from an ordinary content page merely titled
	// "Index of Publications" (whose <h1> is real page content), the same title-only
	// false positive modkit.DetectDirectoryListingServer guards against.
	titleListing := strings.Contains(lower, "<title>") &&
		(strings.Contains(lower, "listing directory") || strings.Contains(lower, "index of"))
	h1Listing := strings.Contains(lower, "<h1>index of") || strings.Contains(lower, "<h1>listing directory")
	if titleListing && h1Listing {
		return true
	}

	// Nginx autoindex: a <pre> block of file links anchored by a parent-directory
	// ("../") entry. The parent link is required so an ordinary <pre> code block
	// that happens to contain a link does not match.
	if strings.Contains(lower, "<pre>") && strings.Contains(lower, "<a href=") && modkit.HasParentDirLink(lower) {
		return true
	}

	// Custom / Express middleware listings that lack an "Index of" heading: a file
	// table or list whose entries include a parent-directory ("../") link — the
	// structural hallmark of a generated index, absent from normal content pages.
	if modkit.HasParentDirLink(lower) && strings.Contains(lower, "<a href=") &&
		(strings.Contains(lower, "<table") || strings.Contains(lower, "<ul")) {
		return true
	}

	return false
}

// get404Hash fetches a known-missing path to fingerprint the 404 page.
func get404Hash(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	notFoundPath := "/vigolium-nonexistent-path-404-check"
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), notFoundPath)
	if err != nil {
		return ""
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	// raw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	return utils.Sha1(resp.Body().String())
}

func buildResult(base, host string, probe probePath, request, response string) *output.ResultEvent {
	matched := fmt.Sprintf("%s%s", base, probe.path)
	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      matched,
		Matched:  matched,
		Request:  request,
		Response: response,
		ExtractedResults: []string{
			fmt.Sprintf("Directory: %s", probe.path),
			fmt.Sprintf("Name: %s", probe.name),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Directory Listing Exposed: %s", probe.name),
			Description: fmt.Sprintf("Directory listing is enabled for the %s directory, potentially exposing sensitive files and internal assets", probe.name),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"directory-listing", "serve-index", "misconfiguration", "information-disclosure"},
			Reference:   []string{"https://expressjs.com/en/resources/middleware/serve-index.html"},
		},
	}
}
