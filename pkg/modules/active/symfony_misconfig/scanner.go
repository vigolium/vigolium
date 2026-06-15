package symfony_misconfig

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
	// Web Profiler
	{
		path: "/_profiler/",
		name: "Symfony Web Profiler",
		// Strong, Symfony-unique markers only — the bare "profiler" slug is a
		// segment of the probe path and reflects on any path-routing page.
		markers: []string{"Symfony Profiler", "sf-toolbar", "X-Debug-Token"},
		sev:     severity.High,
		desc:    "Symfony web profiler exposed, revealing request/response details, routes, and environment configuration",
	},
	{
		path: "/_profiler/empty/search/results",
		name: "Symfony Profiler Search",
		// The page renders inside the profiler chrome — require its Symfony-unique
		// markers rather than the bare "profiler"/"token"/"results" slugs, which are
		// path segments (reflected) or generic words.
		markers: []string{"sf-toolbar", "X-Debug-Token", "Symfony Profiler"},
		sev:     severity.High,
		desc:    "Symfony profiler search endpoint accessible, allowing enumeration of debug tokens",
	},
	// Web Debug Toolbar
	{
		path:    "/_wdt/",
		name:    "Symfony Web Debug Toolbar",
		markers: []string{"sf-toolbar", "Symfony"},
		sev:     severity.High,
		desc:    "Symfony web debug toolbar exposed, leaking environment details and request information",
	},
	// Dev front controller (older Symfony)
	{
		path:    "/app_dev.php/",
		name:    "Symfony Dev Front Controller",
		markers: []string{"Symfony", "sf-toolbar"},
		sev:     severity.High,
		desc:    "Symfony development front controller (app_dev.php) accessible in production, enabling debug features",
	},
	{
		path:    "/app_dev.php/_profiler/",
		name:    "Symfony Dev Profiler",
		markers: []string{"Symfony Profiler", "sf-toolbar"},
		sev:     severity.High,
		desc:    "Symfony development profiler accessible through app_dev.php",
	},
	// Debug logs
	{
		path:        "/var/log/dev.log",
		name:        "Symfony Dev Log",
		markers:     []string{"request.INFO", "security.DEBUG", "doctrine", "WARNING", "CRITICAL"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Symfony development log exposed, revealing application errors, queries, and security events",
	},
	{
		path:        "/var/log/prod.log",
		name:        "Symfony Production Log",
		markers:     []string{"request.INFO", "security.DEBUG", "doctrine", "WARNING", "CRITICAL"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Symfony production log exposed, revealing application errors and security events",
	},
	// Exposed configuration
	{
		path:        "/config/packages/framework.yaml",
		name:        "Symfony Framework Config",
		markers:     []string{"framework:", "secret:", "router:", "session:"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Symfony framework configuration exposed, potentially revealing secret key and internal settings",
	},
	{
		path:        "/config/packages/doctrine.yaml",
		name:        "Symfony Doctrine Config",
		markers:     []string{"doctrine:", "dbal:", "url:", "driver:"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Symfony Doctrine configuration exposed, potentially revealing database connection details",
	},
	{
		path:        "/config/packages/security.yaml",
		name:        "Symfony Security Config",
		markers:     []string{"security:", "firewalls:", "providers:", "access_control:"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Symfony security configuration exposed, revealing authentication and authorization rules",
	},
	// Exposed bundles.php
	{
		path:        "/config/bundles.php",
		name:        "Symfony Bundles Config",
		markers:     []string{"<?php", "return [", "Symfony\\", "Bundle"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Symfony bundles configuration exposed as PHP source, revealing installed bundles",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Symfony Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Symfony Misconfiguration module.
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
		ds: dedup.LazyDiskSet("symfony_misconfig"),
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

// ScanPerRequest probes the host for Symfony-specific misconfiguration files.
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// sub-directory CMS install (e.g. /blog/<file>) is reached, not just the root.
	// Claim each (host, base) pair up front so a fully-deduped request issues no
	// traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeFile(ctx, httpClient, scanCtx, p, base+p.path, fp); result != nil {
				results = append(results, result)
			}
		}
	}
	return results, nil
}

// fingerprint404 fetches a non-existent path to learn what a 404 looks like.
func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-symfony-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a Symfony file and validates the response.
func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p probe,
	probePath string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
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

	// Catch-all / shell guard: a body textually equivalent to the originally
	// observed page means the app routed this sub-path back to its standard shell
	// (a login wall, a landing page) — "the same body with or without the probe".
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
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

	// Strip the reflected probe path before matching: several profiler probe slugs
	// ("profiler", "results", "app_dev.php") are segments of their own path, so a
	// page that echoes the requested URL (a breadcrumb, a JSON "path" field, a
	// <form action>) would otherwise satisfy the marker on reflection alone.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	matched := false
	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(matchBody, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	// Sub-directory catch-all guard: now that we probe under context-path prefixes,
	// drop the finding if a nonexistent sibling under the same parent returns the
	// same markers (a handler that 200s every child path). Root-level probes are
	// already covered by the random-path 404 fingerprint above.
	if modkit.SiblingServesAnyMarker(scanCtx, ctx, httpClient, probePath, p.markers) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Symfony Misconfiguration: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "symfony", "misconfiguration"},
			Reference:   []string{"https://symfony.com/doc/current/reference/configuration/framework.html"},
		},
	}
}
