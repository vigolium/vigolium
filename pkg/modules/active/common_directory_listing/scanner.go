package common_directory_listing

import (
	"fmt"

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

	// Host-wide catch-all guard: a real autoindex server 404s a non-existent
	// directory, so if a random guaranteed-nonexistent dir already renders a
	// listing-shaped body the host templates that body for any path (SPA shell,
	// wildcard rewrite, soft-404) and every per-directory finding is spurious.
	if modkit.RandomDirCatchAll(scanCtx, ctx, httpClient, func(b string) bool { return modkit.DetectDirectoryListingServer(b) != "" }) {
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

		// SetPath/SetMethod produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
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

		// Check for directory listing indicators
		if serverType := modkit.DetectDirectoryListingServer(body); serverType != "" {
			results = append(results, buildResult(base, host, probe, serverType, string(probeRaw), resp.FullResponseString()))
		}

		resp.Close()
	}

	return results, nil
}

// get404Hash fetches a known-missing path to fingerprint the 404 page.
func get404Hash(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	notFoundPath := "/vigolium-nonexistent-path-404-check"
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), notFoundPath)
	if err != nil {
		return ""
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	// SetPath/SetMethod produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	return utils.Sha1(resp.Body().String())
}

func buildResult(base, host string, probe probePath, serverType, request, response string) *output.ResultEvent {
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
