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

	var results []*output.ResultEvent
	target := ctx.Target()

	for _, probe := range probePaths {
		probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probe.path)
		if err != nil {
			continue
		}
		probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

		probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
		if err != nil {
			continue
		}
		probeReq = probeReq.WithService(ctx.Service())

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

		// Check for directory listing indicators
		if isDirectoryListing(body) {
			results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponse().String()))
		}

		resp.Close()
	}

	return results, nil
}

// isDirectoryListing checks the response body for directory listing indicators.
func isDirectoryListing(body string) bool {
	lower := strings.ToLower(body)

	// serve-index markers: HTML title containing "listing directory" or "Index of"
	if strings.Contains(lower, "<title>") {
		if strings.Contains(lower, "listing directory") || strings.Contains(lower, "index of") {
			return true
		}
	}

	// serve-index: table-based file listing with <h1> containing directory path
	if strings.Contains(body, "<h1>") && strings.Contains(body, "<table") && strings.Contains(body, "<a href=") {
		return true
	}

	// Nginx autoindex: <html><head><title>Index of
	if strings.Contains(lower, "<html>") && strings.Contains(lower, "<head>") && strings.Contains(lower, "<title>index of") {
		return true
	}

	// Apache autoindex: <h1>Index of
	if strings.Contains(lower, "<h1>index of") {
		return true
	}

	// <pre> blocks with file listings (common in simple directory listing implementations)
	if strings.Contains(body, "<pre>") && strings.Contains(body, "<a href=") {
		return true
	}

	// Body contains <a href= links AND looks like a directory listing (not a normal page)
	// A directory listing typically has multiple href links and lacks normal page structure
	if strings.Contains(body, "<a href=") &&
		(strings.Contains(lower, "directory") || strings.Contains(lower, "listing")) &&
		!strings.Contains(lower, "<nav") &&
		!strings.Contains(lower, "<footer") {
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

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return ""
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	return utils.Sha1(resp.Body().String())
}

func buildResult(target, host string, probe probePath, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      target,
		Matched:  fmt.Sprintf("%s%s", target, probe.path),
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
