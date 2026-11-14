package laravel_sensitive_files

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
	path    string
	name    string
	markers []string
	// htmlDoc marks a probe whose GENUINE hit is a rendered HTML document (a
	// storage directory listing). Those cannot use the content-type=HTML rejection
	// (their real content IS text/html), so they lean on the decoy/status catch-all
	// confirmation instead. When false (the default) the probe targets a structured
	// resource — an XML/JSON config, a SQLite binary, raw PHP source — that is never
	// served as an HTML *document*, so the truncation-proof content-type gate applies.
	htmlDoc     bool
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
}

// decoyRounds is how many same-directory/same-extension negative-control probes
// the catch-all disproof issues per candidate. A host that answers every sibling
// path with the same 200 body (a reflecting/echo server, an SPA fallback, a
// blanket rewrite) trips at least one round and the candidate is dropped. Two
// rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

// accepts reports whether body carries at least one of this probe's markers.
// Centralized so the primary match and the catch-all decoy disproof run the exact
// same predicate against the candidate and a decoy sibling.
func (p probe) accepts(body string) (matched []string, ok bool) {
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

// markerMatch is the flat-body predicate handed to MultiRoundExtDecoyCatchAll.
func (p probe) markerMatch(body string) bool {
	_, ok := p.accepts(body)
	return ok
}

var probes = []probe{
	// PHPUnit config
	{
		path:        "/phpunit.xml",
		name:        "PHPUnit Config",
		markers:     []string{"<phpunit", "bootstrap", "testsuite", "php_unit"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "PHPUnit configuration file exposed, potentially containing environment variables and internal paths",
		refs:        []string{"https://phpunit.readthedocs.io/en/latest/configuration.html"},
	},
	{
		path:        "/phpunit.xml.dist",
		name:        "PHPUnit Config (dist)",
		markers:     []string{"<phpunit", "bootstrap", "testsuite"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "PHPUnit distribution configuration file exposed, revealing test structure and environment settings",
		refs:        []string{"https://phpunit.readthedocs.io/en/latest/configuration.html"},
	},
	// SQLite database
	{
		path:        "/database/database.sqlite",
		name:        "SQLite Database (database/)",
		markers:     []string{"SQLite format 3"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Laravel SQLite database file is publicly downloadable, exposing the entire application database",
	},
	{
		path:        "/database.sqlite",
		name:        "SQLite Database (root)",
		markers:     []string{"SQLite format 3"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "SQLite database file is publicly downloadable from the web root",
	},
	// Storage framework internals
	{
		path:    "/storage/framework/sessions/",
		name:    "Storage Sessions Directory",
		markers: []string{"Index of", "Parent Directory"},
		htmlDoc: true, // a directory listing is a genuine HTML document
		sev:     severity.Critical,
		desc:    "Laravel session storage directory is listable, enabling session hijacking via file download",
	},
	{
		path:    "/storage/framework/views/",
		name:    "Storage Views Directory",
		markers: []string{"Index of", "Parent Directory"},
		htmlDoc: true, // a directory listing is a genuine HTML document
		sev:     severity.High,
		desc:    "Laravel compiled views directory is listable, potentially exposing application source and template logic",
	},
	{
		path:    "/storage/framework/cache/",
		name:    "Storage Cache Directory",
		markers: []string{"Index of", "Parent Directory"},
		htmlDoc: true, // a directory listing is a genuine HTML document
		sev:     severity.High,
		desc:    "Laravel cache directory is listable, potentially exposing cached data and application state",
	},
	// PHPUnit eval-stdin (CVE-2017-9841)
	{
		path:        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		name:        "PHPUnit eval-stdin.php (CVE-2017-9841)",
		markers:     []string{"phpunit", "PHPUnit", "php://stdin"},
		antiMarkers: []string{"404 Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "PHPUnit eval-stdin.php is publicly accessible (CVE-2017-9841 candidate). This may allow remote code execution if PHP handler processes this file",
		refs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-9841"},
	},
	// Vendor composer installed.json
	{
		path:        "/vendor/composer/installed.json",
		name:        "Composer Installed Packages",
		markers:     []string{"laravel/framework", "packages", "name", "version"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer installed.json is publicly accessible, revealing all dependency names and versions for precise CVE targeting",
	},
	// Wrong document root indicators
	{
		path:        "/artisan",
		name:        "Laravel Artisan (Wrong Docroot)",
		markers:     []string{"#!/usr/bin/env php", "artisan", "Illuminate", "Application"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Laravel artisan script is accessible, indicating the project root is served instead of the public/ directory",
	},
	{
		path:        "/server.php",
		name:        "Laravel server.php (Wrong Docroot)",
		markers:     []string{"<?php", "$_SERVER", "public_path", "server.php"},
		antiMarkers: []string{"<html"},
		sev:         severity.Critical,
		desc:        "Laravel server.php is accessible, indicating the project root is served instead of the public/ directory. PHP source may also be exposed",
	},
	{
		path:        "/routes/web.php",
		name:        "Laravel Routes (Wrong Docroot)",
		markers:     []string{"<?php", "Route::", "Route\\"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Laravel routes file is accessible, exposing all application routes and indicating wrong document root",
	},
	{
		path:        "/config/app.php",
		name:        "Laravel Config (Wrong Docroot)",
		markers:     []string{"<?php", "return [", "'providers'", "'aliases'"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Laravel config/app.php is accessible, exposing application configuration and indicating wrong document root",
	},
	{
		path:        "/bootstrap/app.php",
		name:        "Laravel Bootstrap (Wrong Docroot)",
		markers:     []string{"<?php", "Application", "Illuminate", "bootstrap"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Laravel bootstrap/app.php is accessible, indicating the project root is served instead of the public/ directory",
	},
}

type notFoundFingerprint struct {
	status   int
	bodyHash string
	bodyLen  int
}

// Module implements the Laravel Sensitive Files active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Sensitive Files module.
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
		ds: dedup.LazyDiskSet("laravel_sensitive_files"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeFile(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-laravel-files-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
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
	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}

	return &notFoundFingerprint{
		status:   status,
		bodyHash: hash,
		bodyLen:  len(body),
	}
}

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

	// modifiedRaw is internally built (well-formed), so wrap directly instead
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
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Content-type discipline for a structured (non-document) probe. An XML/JSON
	// config, a SQLite binary, or raw PHP source is never served as an HTML
	// *document*, so a text/html response for it is a catch-all / echo shell —
	// reject it. Truncation-proof: the Content-Type header survives the gzip +
	// bogus Content-Length:0 quirk that captures only a partial body, so this holds
	// even when a weak marker ("name", "version", "bootstrap", an echoed path
	// segment) survives in the truncated tail after the <html>/<!DOCTYPE anti-marker
	// in the head is lost. A directory-listing probe (htmlDoc) serves a genuine HTML
	// document, so it skips this and relies on the decoy catch-all confirmation below.
	if !p.htmlDoc && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
	}

	// Strip the reflected request path before marker matching so a marker that is
	// merely a segment of the probe path echoed back cannot self-match our OWN
	// request. The original body is retained for anti-markers and stored evidence.
	matchedMarkers, matched := p.accepts(modkit.StripReflectedProbePath(body, p.path))
	if !matched {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// sharing this probe's directory AND extension. If a random same-shape path
	// returns the same status and also satisfies the marker predicate, the host
	// serves this content for ANY path (a reflecting/echo server, an SPA fallback,
	// an extension-scoped catch-all) and the match proves nothing. A genuinely
	// exposed file has no such sibling (the decoy 404s), so this costs no true
	// positives, and it is robust to the body-truncation quirk because the decoy is
	// run through the same predicate rather than a body-similarity compare.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, p.markerMatch) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	refs := p.refs
	if len(refs) == 0 {
		refs = []string{"https://laravel.com/docs/structure"}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Laravel Sensitive File: %s", p.name),
			Description: p.desc,
			Severity:    modkit.CapSeverity(p.sev, severity.Medium),
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "sensitive-file", "misconfiguration"},
			Reference:   refs,
		},
	}
}
