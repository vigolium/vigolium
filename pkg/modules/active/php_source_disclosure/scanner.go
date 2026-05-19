package php_source_disclosure

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
	// .phps highlight handler
	{
		path:        "/index.phps",
		name:        "PHP Highlight Source (index.phps)",
		markers:     []string{"<?php", "<code>", "<span style=", "highlight_file", "php_highlight"},
		antiMarkers: []string{"404 Not Found", "Page Not Found"},
		sev:         severity.High,
		desc:        "PHP source highlighting handler (.phps) enabled, exposing syntax-highlighted source code",
	},
	{
		path:        "/config.phps",
		name:        "PHP Highlight Source (config.phps)",
		markers:     []string{"<?php", "<code>", "password", "database", "config"},
		antiMarkers: []string{"404 Not Found", "Page Not Found"},
		sev:         severity.Critical,
		desc:        "PHP source highlighting handler exposing configuration file source code",
	},
	{
		path:        "/login.phps",
		name:        "PHP Highlight Source (login.phps)",
		markers:     []string{"<?php", "<code>", "<span style="},
		antiMarkers: []string{"404 Not Found", "Page Not Found"},
		sev:         severity.High,
		desc:        "PHP source highlighting handler exposing login page source code",
	},
	// PHP served as static/plaintext
	{
		path:        "/index.php",
		name:        "PHP Source as Plaintext (index.php)",
		markers:     []string{"<?php"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<head>", "<body>"},
		sev:         severity.Critical,
		desc:        "PHP files served as plaintext instead of being executed, exposing full source code",
	},
	{
		path:        "/config.php",
		name:        "PHP Config Source Disclosure",
		markers:     []string{"<?php", "$"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<head>"},
		sev:         severity.Critical,
		desc:        "PHP configuration file served as plaintext, potentially exposing credentials",
	},
	{
		path:        "/wp-config.php",
		name:        "WordPress Config Source Disclosure",
		markers:     []string{"<?php", "DB_NAME", "DB_PASSWORD"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "WordPress configuration file served as plaintext, exposing database credentials",
	},
	// Dangerous extension mappings
	{
		path:        "/index.phtml",
		name:        "PHTML Extension Accessible",
		markers:     []string{"<?php", "<?=", "<code>"},
		antiMarkers: []string{"404 Not Found", "Page Not Found", "<html"},
		sev:         severity.High,
		desc:        ".phtml extension files accessible, may expose PHP source or allow execution via upload bypass",
	},
	{
		path:        "/index.php5",
		name:        "PHP5 Extension Accessible",
		markers:     []string{"<?php", "<?="},
		antiMarkers: []string{"404 Not Found", "Page Not Found", "<html"},
		sev:         severity.High,
		desc:        ".php5 extension files accessible, may expose PHP source or allow execution via upload bypass",
	},
	{
		path:        "/index.php7",
		name:        "PHP7 Extension Accessible",
		markers:     []string{"<?php", "<?="},
		antiMarkers: []string{"404 Not Found", "Page Not Found", "<html"},
		sev:         severity.High,
		desc:        ".php7 extension files accessible, may expose PHP source or allow execution via upload bypass",
	},
	// Include files
	{
		path:        "/config.inc",
		name:        "PHP Include File (.inc)",
		markers:     []string{"<?php", "$db", "$password", "$config"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        ".inc include file served as plaintext, potentially exposing configuration and credentials",
	},
	{
		path:        "/db.inc",
		name:        "Database Include File",
		markers:     []string{"<?php", "$db", "mysql", "password", "host"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Database include file served as plaintext, exposing database connection details",
	},
	{
		path:        "/settings.inc",
		name:        "Settings Include File",
		markers:     []string{"<?php", "$"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Settings include file served as plaintext, potentially exposing application configuration",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the PHP Source Disclosure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PHP Source Disclosure module.
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
		ds: dedup.LazyDiskSet("php_source_disclosure"),
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

// ScanPerRequest probes the host for PHP source disclosure files.
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
	randomPath := "/vigolium-phpsrc-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a PHP file and validates the response.
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
		Response:         resp.FullResponse().String(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("PHP Source Disclosure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "source-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
