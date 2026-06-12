package php_debug_exposure

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
	// Additional phpinfo paths (not covered by sensitive_file_discovery which only has /phpinfo.php)
	{
		path:    "/info.php",
		name:    "PHP Info (info.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /info.php, revealing PHP configuration and server details",
	},
	{
		path:    "/test.php",
		name:    "PHP Info (test.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /test.php, revealing PHP configuration and server details",
	},
	{
		path:    "/debug.php",
		name:    "PHP Info (debug.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /debug.php, revealing PHP configuration and server details",
	},
	{
		path:    "/_phpinfo.php",
		name:    "PHP Info (_phpinfo.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /_phpinfo.php, revealing PHP configuration and server details",
	},
	{
		path:    "/public/phpinfo.php",
		name:    "PHP Info (public/phpinfo.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /public/phpinfo.php, revealing PHP configuration and server details",
	},
	{
		path:    "/php_info.php",
		name:    "PHP Info (php_info.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /php_info.php, revealing PHP configuration and server details",
	},
	{
		path:    "/i.php",
		name:    "PHP Info (i.php)",
		markers: []string{"PHP Version", "phpinfo()", "Configuration File"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed at /i.php, revealing PHP configuration and server details",
	},
	// PHP-FPM status endpoints
	{
		path:    "/fpm-status",
		name:    "PHP-FPM Status",
		markers: []string{"pool:", "accepted conn:", "listen queue:"},
		sev:     severity.Medium,
		desc:    "PHP-FPM status page exposed, revealing pool configuration and connection details",
	},
	{
		path:    "/php-fpm-status",
		name:    "PHP-FPM Status (alt)",
		markers: []string{"pool:", "accepted conn:", "listen queue:"},
		sev:     severity.Medium,
		desc:    "PHP-FPM status page exposed at alternate path, revealing pool configuration",
	},
	{
		path:    "/status?full",
		name:    "PHP-FPM Full Status",
		markers: []string{"pool:", "pid:", "request uri:"},
		sev:     severity.Medium,
		desc:    "PHP-FPM full status page exposed, revealing active request details and script paths",
	},
	{
		path:        "/ping",
		name:        "PHP-FPM Ping",
		markers:     []string{"pong"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "{"},
		sev:         severity.Low,
		desc:        "PHP-FPM ping endpoint exposed, confirming PHP-FPM is running",
	},
	// phpMyAdmin paths (not covered by sensitive_file_discovery)
	{
		path:    "/phpmyadmin/",
		name:    "phpMyAdmin",
		markers: []string{"phpMyAdmin", "pma_", "PMA_"},
		sev:     severity.Medium,
		desc:    "phpMyAdmin database management interface exposed, enabling potential database compromise",
	},
	{
		path:    "/pma/",
		name:    "phpMyAdmin (pma)",
		markers: []string{"phpMyAdmin", "pma_", "PMA_"},
		sev:     severity.Medium,
		desc:    "phpMyAdmin exposed at /pma/, enabling potential database compromise",
	},
	{
		path:    "/mysql/",
		name:    "phpMyAdmin (mysql)",
		markers: []string{"phpMyAdmin", "pma_", "PMA_"},
		sev:     severity.Medium,
		desc:    "phpMyAdmin exposed at /mysql/, enabling potential database compromise",
	},
	{
		path:    "/myadmin/",
		name:    "phpMyAdmin (myadmin)",
		markers: []string{"phpMyAdmin", "pma_", "PMA_"},
		sev:     severity.Medium,
		desc:    "phpMyAdmin exposed at /myadmin/, enabling potential database compromise",
	},
	{
		path:    "/dbadmin/",
		name:    "phpMyAdmin (dbadmin)",
		markers: []string{"phpMyAdmin", "pma_", "PMA_"},
		sev:     severity.Medium,
		desc:    "phpMyAdmin exposed at /dbadmin/, enabling potential database compromise",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the PHP Debug Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PHP Debug Exposure module.
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
		ds: dedup.LazyDiskSet("php_debug_exposure"),
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

// ScanPerRequest probes the host for PHP-specific debug and admin endpoints.
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
	randomPath := "/vigolium-php-debug-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a PHP debug endpoint and validates the response.
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
			Name:        fmt.Sprintf("PHP Debug Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "debug", "misconfiguration"},
			Reference:   []string{"https://www.php.net/manual/en/function.phpinfo.php"},
		},
	}
}
