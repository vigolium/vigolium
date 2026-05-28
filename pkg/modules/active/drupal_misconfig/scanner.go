package drupal_misconfig

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
	// Settings/config source disclosure
	{
		path:        "/sites/default/settings.php",
		name:        "Drupal settings.php Source",
		markers:     []string{"$databases", "$settings", "drupal_hash_salt"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Drupal settings.php source code exposed, containing database credentials and hash salt",
	},
	{
		path:    "/sites/default/services.yml",
		name:    "Drupal services.yml",
		markers: []string{"services:", "parameters:", "twig.config"},
		sev:     severity.High,
		desc:    "Drupal services.yml exposed, revealing service container configuration",
	},
	{
		path:    "/sites/development.services.yml",
		name:    "Drupal Development Services",
		markers: []string{"services:", "parameters:", "debug"},
		sev:     severity.Medium,
		desc:    "Drupal development services file exposed, indicating development configuration active",
	},
	// Update/install/authorize scripts
	{
		path:        "/update.php",
		name:        "Drupal update.php",
		markers:     []string{"update", "Drupal", "database"},
		antiMarkers: []string{"Access denied", "403 Forbidden"},
		sev:         severity.High,
		desc:        "Drupal update.php accessible without authentication, exposing upgrade workflows",
	},
	{
		path:        "/install.php",
		name:        "Drupal 7 Installer",
		markers:     []string{"install", "Drupal", "database", "Choose language"},
		antiMarkers: []string{"already installed"},
		sev:         severity.Critical,
		desc:        "Drupal installer accessible, potentially allowing re-installation",
	},
	{
		path:        "/core/install.php",
		name:        "Drupal 8+ Installer",
		markers:     []string{"install", "Drupal", "Choose language", "Select an installation profile"},
		antiMarkers: []string{"already installed"},
		sev:         severity.Critical,
		desc:        "Drupal 8+ installer accessible, potentially allowing re-installation",
	},
	{
		path:        "/authorize.php",
		name:        "Drupal authorize.php",
		markers:     []string{"authorize", "Drupal", "Update manager"},
		antiMarkers: []string{"Access denied"},
		sev:         severity.High,
		desc:        "Drupal authorize.php accessible, enabling module/theme installation",
	},
	// Version/info disclosure
	{
		path:    "/CHANGELOG.txt",
		name:    "Drupal CHANGELOG",
		markers: []string{"Drupal", "Bug fixes", "Changes since"},
		sev:     severity.Low,
		desc:    "Drupal CHANGELOG.txt exposed, revealing exact core version",
	},
	{
		path:    "/README.txt",
		name:    "Drupal README",
		markers: []string{"Drupal", "open source", "content-management"},
		sev:     severity.Info,
		desc:    "Drupal README.txt exposed, confirming Drupal installation",
	},
	{
		path:    "/INSTALL.txt",
		name:    "Drupal INSTALL",
		markers: []string{"Drupal", "REQUIREMENTS", "INSTALLATION"},
		sev:     severity.Info,
		desc:    "Drupal INSTALL.txt exposed, confirming Drupal installation",
	},
	// Config sync directory (Drupal 8+)
	{
		path:    "/config/sync/system.site.yml",
		name:    "Drupal Config Sync Export",
		markers: []string{"uuid:", "name:", "mail:", "slogan:"},
		sev:     severity.Critical,
		desc:    "Drupal configuration sync directory exposed, leaking site configuration including module list and settings",
	},
	// Public files directory listing
	{
		path:    "/sites/default/files/",
		name:    "Drupal Public Files Directory",
		markers: []string{"Index of", "Parent Directory", "<tr>"},
		sev:     severity.Medium,
		desc:    "Drupal public files directory listing enabled, potentially exposing uploaded documents and backups",
	},
	// .htaccess protection check
	{
		path:    "/sites/default/files/.htaccess",
		name:    "Drupal Files .htaccess",
		markers: []string{"SetHandler", "Require all denied", "Options", "ForceType"},
		sev:     severity.Medium,
		desc:    "Drupal files .htaccess downloadable, indicating potential protection bypass on non-Apache servers",
	},
	// Debug log
	{
		path:        "/sites/default/files/debug.log",
		name:        "Drupal Debug Log",
		markers:     []string{"[error]", "Exception", "Warning:", "Notice:"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Drupal debug log exposed, potentially containing sensitive error details and file paths",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Drupal Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Drupal Misconfiguration module.
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
		ds: dedup.LazyDiskSet("drupal_misconfig"),
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

// ScanPerRequest probes the host for Drupal-specific misconfiguration files.
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
	randomPath := "/vigolium-drupal-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a Drupal file and validates the response.
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
			Name:        fmt.Sprintf("Drupal Misconfiguration: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"cms", "drupal", "misconfiguration"},
			Reference:   []string{"https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-your-site"},
		},
	}
}
