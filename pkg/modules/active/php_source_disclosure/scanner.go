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

// decoyRounds is how many same-directory/same-extension negative-control probes
// the catch-all disproof issues per candidate. A host that answers every
// /<dir>/<anything>.<ext> with the same 200 body (a reflecting/echo server, a SPA
// fallback, a blanket rewrite) trips at least one round and the candidate is
// dropped. Two rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type probe struct {
	path    string
	name    string
	markers []string
	// htmlDoc marks a probe whose GENUINE hit is legitimately an HTML document — the
	// .phps / .phtml source *highlighter* output, which PHP renders as HTML
	// (<code><span style=...>). Those skip the content-type gate and rely on the
	// catch-all decoy disproof. When false (raw PHP source served as plaintext:
	// .php/.php5/.php7/.inc), a text/html response is NOT a genuine source leak — it
	// is executed output or a catch-all / echo shell — so it is rejected outright by
	// content-type. This aligns with the existing <html/<!DOCTYPE anti-markers (the
	// module already treats an HTML response as "not a source leak") and, crucially,
	// survives the body-truncation quirk that strips those head anti-markers, where a
	// weak marker (<?php, $, "password") would otherwise forge a match in the tail.
	htmlDoc     bool
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

// match reports whether body satisfies this probe's marker set (pure-OR: any
// single marker hit confirms) and returns the matched substrings for evidence.
// Centralized so the primary match and the catch-all decoy disproof apply the
// exact same predicate.
func (p probe) match(body string) (matched []string, ok bool) {
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

var probes = []probe{
	// .phps highlight handler
	{
		path:    "/index.phps",
		name:    "PHP Highlight Source (index.phps)",
		markers: []string{"<?php", "<code>", "<span style=", "highlight_file", "php_highlight"},
		// The .phps highlighter renders HTML, so rely on the catch-all decoy disproof
		// rather than a content-type gate that would reject the genuine hit.
		htmlDoc:     true,
		antiMarkers: []string{"404 Not Found", "Page Not Found"},
		sev:         severity.High,
		desc:        "PHP source highlighting handler (.phps) enabled, exposing syntax-highlighted source code",
	},
	{
		path:        "/config.phps",
		name:        "PHP Highlight Source (config.phps)",
		markers:     []string{"<?php", "<code>", "password", "database", "config"},
		htmlDoc:     true,
		antiMarkers: []string{"404 Not Found", "Page Not Found"},
		sev:         severity.Critical,
		desc:        "PHP source highlighting handler exposing configuration file source code",
	},
	{
		path:        "/login.phps",
		name:        "PHP Highlight Source (login.phps)",
		markers:     []string{"<?php", "<code>", "<span style="},
		htmlDoc:     true,
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
		path:    "/index.phtml",
		name:    "PHTML Extension Accessible",
		markers: []string{"<?php", "<?=", "<code>"},
		// .phtml source may be served highlighted (HTML), so skip the content-type gate
		// and let the catch-all decoy disproof guard it.
		htmlDoc:     true,
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

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
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

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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

	// Content-type discipline for the plaintext-source probes (survives body
	// truncation — the header is intact even when a gzip/Content-Length-0 quirk leaves
	// only a partial body tail): raw PHP source disclosed as .php/.php5/.php7/.inc is
	// served as text/plain (or a non-HTML PHP mime), never as an HTML *document*. A
	// text/html response is either executed output or a universal catch-all / echo
	// shell whose truncated tail carries a weak marker (<?php, $, "password"); reject
	// it outright. This is the truncation-proof form of the existing <html/<!DOCTYPE
	// anti-markers. The .phps/.phtml highlighter output IS genuine HTML (htmlDoc), so
	// those skip this gate and rely on the catch-all decoy disproof below.
	if !p.htmlDoc && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
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

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
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

	// Strip the reflected request from the body before marker matching: a host that
	// echoes the requested path or the request body would otherwise let an echoed
	// value satisfy a marker (the path /config.php echoing "config", a request body
	// carrying "password"/"$db"). The original body is kept for anti-markers and
	// stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	matchedMarkers, ok := p.match(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// sharing this file's directory AND extension. If a random same-shape path returns
	// the same status and also satisfies the marker predicate, the host serves this
	// content for any path (a reflecting/echo server, a SPA fallback, an
	// extension-scoped catch-all) and the match proves nothing. A genuinely disclosed
	// source file has no such sibling (the decoy 404s), so this costs no true
	// positives, and it is robust to the body-truncation quirk because the decoy is run
	// through the same predicate rather than a body-similarity compare. This is the
	// guard for the .phps/.phtml probes that cannot use the content-type gate.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := p.match(b)
		return sibOK
	}) {
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
			Name:        fmt.Sprintf("PHP Source Disclosure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "source-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
