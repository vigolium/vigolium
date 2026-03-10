package common_directory_listing

import (
	"fmt"
	"regexp"
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

// probePaths is the list of common directories to test across web servers.
var probePaths = []probePath{
	{path: "/", name: "root"},
	{path: "/uploads/", name: "uploads"},
	{path: "/files/", name: "files"},
	{path: "/sites/", name: "sites"},
	{path: "/assets/", name: "assets"},
	{path: "/static/", name: "static"},
	{path: "/META-INF/", name: "META-INF"},
	{path: "/WEB-INF/", name: "WEB-INF"},
	{path: "/aspnet_client/", name: "aspnet_client"},
	{path: "/App_Data/", name: "App_Data"},
}

// iisPattern matches IIS default directory listing HTML structure.
var iisPattern = regexp.MustCompile(`</title></head><body><H1>.*?-.*?</H1><hr>`)

// genericListingPattern matches generic directory listing titles like:
// <title>listing directory /ftp/</title>, <title>Directory listing for /</title>,
// <title>Index of /uploads</title>, <title>Directory: /path</title>
var genericListingPattern = regexp.MustCompile(`(?i)<title>\s*(?:(?:listing|index)\s+(?:of|directory)|directory\s+(?:listing|index|of))\b`)

// Module implements the common directory listing exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Common Directory Listing module.
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
		ds: dedup.LazyDiskSet("common_directory_listing"),
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
		if serverType := detectDirectoryListing(body); serverType != "" {
			results = append(results, buildResult(target, host, probe, serverType, string(probeRaw), resp.FullResponse().String()))
		}

		resp.Close()
	}

	return results, nil
}

// detectDirectoryListing checks the response body for server-specific directory listing indicators.
// Returns the server type string if detected, empty string otherwise.
func detectDirectoryListing(body string) string {
	lower := strings.ToLower(body)

	// Jetty: <title>Directory: AND jetty-dir.css
	if strings.Contains(lower, "<title>directory:") && strings.Contains(lower, "jetty-dir.css") {
		return "Jetty"
	}

	// IIS: </title></head><body><H1>...-...</H1><hr>
	if iisPattern.MatchString(body) {
		return "IIS"
	}

	// Apache: <title>Index of AND <h1>Index of
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<h1>index of") {
		return "Apache"
	}

	// Nginx: <title>Index of AND <pre>
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<pre>") {
		return "Nginx"
	}

	// Generic catch-all: matches title patterns like "listing directory", "directory listing",
	// "index of", "directory of", etc. Covers Express serve-index, Python SimpleHTTPServer,
	// and other servers with directory listing titles.
	if genericListingPattern.MatchString(body) {
		return "Generic"
	}

	return ""
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

func buildResult(target, host string, probe probePath, serverType, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      target,
		Matched:  fmt.Sprintf("%s%s", target, probe.path),
		Request:  request,
		Response: response,
		ExtractedResults: []string{
			fmt.Sprintf("Directory: %s", probe.path),
			fmt.Sprintf("Server: %s", serverType),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Directory Listing Exposed: %s (%s)", probe.name, serverType),
			Description: fmt.Sprintf("Directory listing is enabled for the %s directory on %s, potentially exposing sensitive files and internal assets", probe.name, serverType),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"directory-listing", "misconfiguration", "information-disclosure"},
			Reference: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
			},
		},
	}
}
