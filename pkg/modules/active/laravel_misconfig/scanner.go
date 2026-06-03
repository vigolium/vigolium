package laravel_misconfig

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// Debug mode (Ignition error page)
	{
		path:    "/vigolium-trigger-laravel-error-" + "probe",
		name:    "Laravel Debug Mode (Ignition)",
		markers: []string{"Ignition", "Spatie\\LaravelIgnition", "Illuminate\\", "vendor/laravel", "APP_KEY"},
		sev:     severity.High,
		desc:    "Laravel debug mode is enabled, exposing Ignition error pages with stack traces, environment variables, and file paths",
	},
	// Whoops error handler (older Laravel)
	{
		path:    "/vigolium-trigger-whoops-error-probe",
		name:    "Laravel Debug Mode (Whoops)",
		markers: []string{"Whoops\\", "filp/whoops", "Illuminate\\", "vendor/laravel"},
		sev:     severity.High,
		desc:    "Laravel debug mode is enabled with Whoops error handler, exposing stack traces and application internals",
	},
	// Debugbar
	{
		path:    "/_debugbar/open",
		name:    "Laravel Debugbar Open",
		markers: []string{"debugbar", "queries", "route", "PhpDebugBar"},
		sev:     severity.High,
		desc:    "Laravel Debugbar open endpoint exposed, potentially leaking SQL queries, routes, and request data",
	},
	{
		path:    "/_debugbar/assets/stylesheets",
		name:    "Laravel Debugbar Assets",
		markers: []string{"debugbar", "phpdebugbar", ".phpdebugbar"},
		sev:     severity.Medium,
		desc:    "Laravel Debugbar assets accessible, confirming Debugbar is enabled in production",
	},
	{
		path:    "/_debugbar/assets/javascript",
		name:    "Laravel Debugbar JS",
		markers: []string{"PhpDebugBar", "debugbar", "DebugBar"},
		sev:     severity.Medium,
		desc:    "Laravel Debugbar JavaScript assets accessible, confirming Debugbar is enabled in production",
	},
	// Application logs
	{
		path:        "/storage/logs/laravel.log",
		name:        "Laravel Application Log",
		markers:     []string{"[stacktrace]", "local.ERROR", "production.ERROR", "Illuminate\\"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Laravel application log exposed, potentially containing stack traces, secrets, and user data",
	},
	// Telescope
	{
		path:        "/telescope",
		name:        "Laravel Telescope Dashboard",
		markers:     []string{"telescope", "Laravel Telescope", "app.js"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Laravel Telescope debugging dashboard exposed, revealing requests, queries, and application internals",
	},
	{
		path:    "/telescope/requests",
		name:    "Laravel Telescope Requests",
		markers: []string{"telescope", "entries", "content"},
		sev:     severity.High,
		desc:    "Laravel Telescope requests endpoint exposed, revealing all HTTP request/response pairs",
	},
	// Horizon
	{
		path:        "/horizon",
		name:        "Laravel Horizon Dashboard",
		markers:     []string{"horizon", "Laravel Horizon", "app.js"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Medium,
		desc:        "Laravel Horizon queue dashboard exposed, revealing job queue configuration and status",
	},
	// Exposed .env via storage symlink
	{
		path:        "/storage/.env",
		name:        "Laravel Storage .env",
		markers:     []string{"APP_KEY=", "DB_", "MAIL_"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Environment file exposed via Laravel storage symlink",
	},
	// Debug log in alternate location
	{
		path:        "/storage/logs/debug.log",
		name:        "Laravel Debug Log",
		markers:     []string{"[stacktrace]", "DEBUG", "ERROR", "Illuminate\\"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Laravel debug log exposed, potentially containing sensitive debugging information",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Laravel Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Misconfiguration module.
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
		ds: dedup.LazyDiskSet("laravel_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to bypass default URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for Laravel-specific misconfiguration files.
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

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeFile(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

// fingerprint404 fetches a non-existent path to learn what a 404 looks like.
func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-laravel-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))

	status := 0
	contentType := ""
	if resp.Response() != nil {
		status = resp.Response().StatusCode
		contentType = strings.ToLower(resp.Response().Header.Get("Content-Type"))
	}

	return &notFoundFingerprint{
		status:      status,
		bodyHash:    hash,
		bodyLen:     len(body),
		contentType: contentType,
	}
}

// probeFile sends a GET request for a Laravel file and validates the response.
func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode

	// Skip error responses
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	// Skip redirects to login
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	// Check against 404 fingerprint
	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil // same content as 404 page
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil // body length within 5% of 404 page
			}
		}
	}

	// Check anti-markers
	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	// Require status 200 and at least one marker match
	if status != 200 {
		return nil
	}

	matched := false
	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Laravel Misconfiguration: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "misconfiguration"},
			Reference:   []string{"https://laravel.com/docs/configuration"},
		},
	}
}
