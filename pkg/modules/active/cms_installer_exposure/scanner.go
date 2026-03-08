package cms_installer_exposure

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
	cms         string
	markers     []string
	antiMarkers []string
	desc        string
}

var probes = []probe{
	// WordPress
	{
		path:        "/wp-admin/install.php",
		name:        "WordPress Installer",
		cms:         "wordpress",
		markers:     []string{"WordPress", "wp-install", "language", "setup-config", "install.php"},
		antiMarkers: []string{"Log In", "wp-login", "already installed"},
		desc:        "WordPress installation wizard is publicly accessible, potentially allowing CMS re-installation",
	},
	{
		path:        "/wp-admin/setup-config.php",
		name:        "WordPress Setup Config",
		cms:         "wordpress",
		markers:     []string{"WordPress", "setup-config", "database", "wp-config"},
		antiMarkers: []string{"Log In", "wp-login"},
		desc:        "WordPress setup configuration wizard is publicly accessible",
	},
	// Drupal 7
	{
		path:        "/install.php",
		name:        "Drupal 7 Installer",
		cms:         "drupal",
		markers:     []string{"Drupal", "Choose language", "installation profile", "install_configure_form"},
		antiMarkers: []string{"already installed", "Access denied"},
		desc:        "Drupal 7 installation wizard is publicly accessible, potentially allowing CMS re-installation",
	},
	// Drupal 8+
	{
		path:        "/core/install.php",
		name:        "Drupal 8+ Installer",
		cms:         "drupal",
		markers:     []string{"Drupal", "Choose language", "Select an installation profile", "install_configure_form"},
		antiMarkers: []string{"already installed", "Access denied"},
		desc:        "Drupal 8+ installation wizard is publicly accessible, potentially allowing CMS re-installation",
	},
	// Joomla
	{
		path:        "/installation/index.php",
		name:        "Joomla Installer",
		cms:         "joomla",
		markers:     []string{"Joomla", "installation", "Configuration", "Database", "site_name"},
		antiMarkers: []string{"404", "not found"},
		desc:        "Joomla installation wizard is publicly accessible, potentially allowing CMS re-installation or reconfiguration",
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the CMS Installer Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CMS Installer Exposure module.
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
		ds: dedup.LazyDiskSet("cms_installer_exposure"),
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

// ScanPerRequest probes the host for exposed CMS installer endpoints.
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
		if result := m.probeInstaller(ctx, httpClient, p, fp); result != nil {
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
	randomPath := "/vigolium-installer-404-" + utils.RandomString(8)

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
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

// probeInstaller sends a GET request for an installer endpoint and validates the response.
func (m *Module) probeInstaller(
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

	// Skip error and auth-required responses
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	// Skip redirects to login/user pages
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
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
			Name:        fmt.Sprintf("CMS Installer Exposed: %s", p.name),
			Description: p.desc,
			Severity:    severity.Critical,
			Confidence:  ModuleConfidence,
			Tags:        []string{"cms", p.cms, "installer", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
