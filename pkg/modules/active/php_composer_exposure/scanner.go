package php_composer_exposure

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
// /<dir>/<anything>.<ext> with the same 200 body (a reflecting/echo server, a
// SPA fallback, a blanket rewrite) trips at least one round and the candidate is
// dropped. Two rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type probe struct {
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Composer JSON files share
	// generic keys ("name","version") with almost any JSON payload, so each probe
	// anchors on a Composer-specific key and corroborates with a second group.
	markers [][]string
	// htmlDoc marks a probe whose GENUINE hit is legitimately an HTML document (the
	// /vendor/ directory listing). For every other probe the target is a JSON
	// manifest, a raw PHP source file, or a plaintext LICENSE — none of which is
	// ever served as an HTML *document* — so a text/html response is a catch-all /
	// echo shell and is rejected outright by content-type (see probeFile). This
	// content-type discipline is the decisive, zero-false-negative guard against the
	// universal-catch-all FP even when a gzip/Content-Length-0 transport quirk leaves
	// only a truncated body tail (the Content-Type header survives truncation).
	htmlDoc     bool
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// Composer manifests
	{
		path: "/composer.json",
		name: "Composer Manifest",
		// "require"/"autoload"/"require-dev" are Composer-specific JSON keys; bare
		// "name" matched any JSON object.
		markers:     [][]string{{`"require"`, `"autoload"`, `"require-dev"`, `"minimum-stability"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer manifest exposed, revealing project dependencies and potentially private repository URLs",
	},
	{
		path: "/composer.lock",
		name: "Composer Lock File",
		// "_readme"/"content-hash" are unique to a composer.lock; require one of
		// those plus a package-detail key so a generic JSON cannot match on "name".
		markers:     [][]string{{`"_readme"`, `"content-hash"`, `"packages"`}, {`"dist"`, `"reference"`, `"source"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer lock file exposed, revealing exact dependency versions for CVE correlation",
	},
	// Vendor directory
	{
		path:    "/vendor/",
		name:    "Vendor Directory Listing",
		markers: [][]string{{"Index of", "Parent Directory", "autoload"}},
		// A directory listing is genuinely an HTML document, so the content-type
		// gate must not reject it; the catch-all disproof (a random sibling under
		// /vendor/ that also "lists") is what protects this probe instead.
		htmlDoc: true,
		sev:     severity.High,
		desc:    "Composer vendor directory listing enabled, exposing all installed packages",
	},
	{
		path: "/vendor/autoload.php",
		name: "Vendor Autoload",
		// ComposerAutoloader/getLoader are the disclosure; drop bare "<?php".
		markers:     [][]string{{"ComposerAutoloader", "getLoader", "composerRequire", "autoload_real"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Composer autoload.php accessible, indicating vendor directory is web-reachable",
	},
	{
		path: "/vendor/composer/installed.json",
		name: "Composer Installed Metadata",
		// "dev-package-names" is unique to a Composer v2 installed.json; require a
		// packages anchor plus a package-detail key.
		markers:     [][]string{{`"dev-package-names"`, `"packages"`}, {`"version_normalized"`, `"install-path"`, `"dist"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer installed.json exposed, listing all packages with exact versions",
	},
	{
		path: "/vendor/composer/installed.php",
		name: "Composer Installed PHP",
		// The disclosure is the raw PHP returning Composer's metadata array.
		markers:     [][]string{{"<?php"}, {"'pretty_version'", "'install_path'", "'reference'", "InstalledVersions"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer installed.php exposed, listing all installed package versions",
	},
	{
		path:        "/vendor/composer/autoload_classmap.php",
		name:        "Composer Classmap",
		markers:     [][]string{{"<?php"}, {"$vendorDir", "$baseDir", "return array"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer autoload classmap exposed, revealing internal class structure and file paths",
	},
	// PHPUnit dev endpoint (CVE-2017-9841)
	{
		path:        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		name:        "PHPUnit eval-stdin.php",
		markers:     [][]string{{"php://stdin", "php://input", "eval-stdin"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "PHPUnit eval-stdin.php exposed, potentially allowing remote code execution (CVE-2017-9841)",
	},
	// Other common vendor files
	{
		path:        "/vendor/composer/LICENSE",
		name:        "Composer License",
		markers:     [][]string{{"Nils Adermann", "Jordi Boggiano"}, {"MIT License", "Composer"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Composer LICENSE file accessible, confirming vendor directory is web-reachable",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the PHP Composer Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PHP Composer Exposure module.
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
		ds: dedup.LazyDiskSet("php_composer_exposure"),
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

// ScanPerRequest probes the host for exposed Composer artifacts.
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
	randomPath := "/vigolium-composer-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a Composer artifact and validates the response.
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

	// Content-type discipline (survives body truncation — the header is intact even
	// when a gzip/Content-Length-0 quirk leaves only a partial body tail): every
	// probe except the /vendor/ directory listing targets a JSON manifest, a raw PHP
	// source file, or a plaintext LICENSE, none of which is EVER served as an HTML
	// *document*. A universal catch-all / reflecting host answers arbitrary paths
	// with its themed text/html shell, and a weak marker (`"require"`, `<?php`,
	// "autoload") that survives in that shell's truncated tail would otherwise forge
	// a match. Rejecting text/html is the decisive, zero-false-negative guard for
	// that class — a real Composer artifact simply never comes back as a document.
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
	// echoes the requested path or the request body back into its response would
	// otherwise let an echoed value satisfy a marker (the path /vendor/autoload.php
	// echoing "autoload", or a request body carrying `"require"`). The original body
	// is kept for anti-markers and stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	// Require every marker group (Composer-specific anchor + corroboration), so a
	// generic JSON body sharing a key like "name"/"version" cannot match.
	matchedMarkers, ok := modkit.MatchAllGroups(matchBody, p.markers)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// sharing this probe's directory AND extension (e.g. /vigolium-decoy-*.json for
	// /composer.json, /vendor/vigolium-decoy-* for /vendor/). If a random same-shape
	// path returns the same status and also satisfies the marker groups, the host
	// serves this content for any path (a reflecting/echo server, a SPA fallback, an
	// extension-scoped catch-all) and the match proves nothing. A genuinely exposed
	// artifact has no such sibling (the decoy 404s), so this costs no true positives,
	// and it is robust to the body-truncation quirk because the decoy is run through
	// the same predicate rather than a body-similarity compare.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := modkit.MatchAllGroups(b, p.markers)
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
			Name:        fmt.Sprintf("PHP Composer Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "composer", "dependency-exposure"},
			Reference:   []string{"https://getcomposer.org/doc/"},
		},
	}
}
