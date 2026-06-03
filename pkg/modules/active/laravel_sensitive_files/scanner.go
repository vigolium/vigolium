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
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
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
		sev:     severity.Critical,
		desc:    "Laravel session storage directory is listable, enabling session hijacking via file download",
	},
	{
		path:    "/storage/framework/views/",
		name:    "Storage Views Directory",
		markers: []string{"Index of", "Parent Directory"},
		sev:     severity.High,
		desc:    "Laravel compiled views directory is listable, potentially exposing application source and template logic",
	},
	{
		path:    "/storage/framework/cache/",
		name:    "Storage Cache Directory",
		markers: []string{"Index of", "Parent Directory"},
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

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
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

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

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
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "sensitive-file", "misconfiguration"},
			Reference:   refs,
		},
	}
}
