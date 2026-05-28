package php_framework_debug

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
	// Yii Debug Module
	{
		path:    "/debug/default/index",
		name:    "Yii Debug Module",
		markers: []string{"Yii Debugger", "yii-debug", "debug-panel", "yii\\debug"},
		sev:     severity.High,
		desc:    "Yii debug module exposed, revealing request logs, database queries, and application configuration",
	},
	{
		path:        "/debug/",
		name:        "Yii Debug Dashboard",
		markers:     []string{"Yii Debugger", "debug-panel", "yii\\debug"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Yii debug dashboard exposed, revealing application internals",
	},
	// Yii Gii Code Generator
	{
		path:    "/gii",
		name:    "Yii Gii Code Generator",
		markers: []string{"Gii", "Code Generator", "gii-panel", "yii\\gii"},
		sev:     severity.Critical,
		desc:    "Yii Gii code generator exposed in production, potentially allowing code generation and modification",
	},
	{
		path:    "/gii/default/index",
		name:    "Yii Gii Index",
		markers: []string{"Gii", "Code Generator", "Model Generator", "CRUD Generator"},
		sev:     severity.Critical,
		desc:    "Yii Gii code generator index accessible, listing available generators",
	},
	// CodeIgniter
	{
		path:    "/user_guide/",
		name:    "CodeIgniter User Guide",
		markers: []string{"CodeIgniter", "User Guide", "user_guide"},
		sev:     severity.Low,
		desc:    "CodeIgniter user guide shipped to production, confirming framework and potentially revealing version",
	},
	{
		path:        "/application/logs/log-",
		name:        "CodeIgniter Application Log",
		markers:     []string{"ERROR", "DEBUG", "INFO", "CRITICAL"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "CodeIgniter application log accessible, potentially exposing error details and file paths",
	},
	// CakePHP Debug Kit
	{
		path:    "/debug_kit/toolbar/",
		name:    "CakePHP Debug Kit Toolbar",
		markers: []string{"debug_kit", "DebugKit", "toolbar", "CakePHP"},
		sev:     severity.High,
		desc:    "CakePHP Debug Kit toolbar exposed, revealing SQL queries, routes, and application variables",
	},
	{
		path:    "/debug_kit/panels/",
		name:    "CakePHP Debug Kit Panels",
		markers: []string{"debug_kit", "DebugKit", "panel", "CakePHP"},
		sev:     severity.High,
		desc:    "CakePHP Debug Kit panels accessible, exposing detailed debugging information",
	},
	// Slim Framework
	{
		path:    "/vigolium-slim-error-probe",
		name:    "Slim Framework Debug",
		markers: []string{"Slim Application Error", "slim/slim", "SlimException"},
		sev:     severity.Medium,
		desc:    "Slim framework debug mode enabled, exposing detailed error pages with stack traces",
	},
	// FuelPHP
	{
		path:    "/fuel/app/logs/",
		name:    "FuelPHP Application Logs",
		markers: []string{"Index of", "Parent Directory", ".log"},
		sev:     severity.Medium,
		desc:    "FuelPHP application logs directory listing enabled, exposing error logs",
	},
	// Phalcon DevTools
	{
		path:    "/webtools.php",
		name:    "Phalcon DevTools",
		markers: []string{"Phalcon", "WebTools", "DevTools", "phalcon"},
		sev:     severity.High,
		desc:    "Phalcon DevTools exposed in production, allowing database migration and code scaffolding",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the PHP Framework Debug Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PHP Framework Debug Exposure module.
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
		ds: dedup.LazyDiskSet("php_framework_debug"),
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

// ScanPerRequest probes the host for PHP framework debug endpoints.
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
	randomPath := "/vigolium-phpfw-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a framework debug endpoint and validates the response.
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
			Name:        fmt.Sprintf("PHP Framework Debug Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "framework", "debug"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
