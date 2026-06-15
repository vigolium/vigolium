package joomla_misconfig

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
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Joomla's JSON/XML surfaces
	// share generic keys ("success"/"message"/"data", "name"/"version", "<version>")
	// with almost any payload, so each anchors on a Joomla/Composer-specific token.
	// Directory-listing probes keep a single OR group — "Index of" already means a
	// real autoindex page, which is the finding.
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// Configuration backups — anchor on the JConfig class / Joomla-specific keys so
	// a generic PHP file carrying a bare $password var cannot match.
	{
		path:        "/configuration.php~",
		name:        "Joomla Config Backup (~)",
		markers:     [][]string{{"JConfig", "$secret", "$sitename", "$mailfrom"}, {"$host", "$user", "$db", "$password"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Joomla configuration.php editor backup exposed, containing database credentials and secret key",
	},
	{
		path:        "/configuration.php.bak",
		name:        "Joomla Config Backup (.bak)",
		markers:     [][]string{{"JConfig", "$secret", "$sitename", "$mailfrom"}, {"$host", "$user", "$db", "$password"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Joomla configuration.php backup exposed, containing database credentials and secret key",
	},
	{
		path:        "/configuration.php.old",
		name:        "Joomla Config Backup (.old)",
		markers:     [][]string{{"JConfig", "$secret", "$sitename", "$mailfrom"}, {"$host", "$user", "$db", "$password"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Joomla configuration.php old backup exposed, containing database credentials and secret key",
	},
	// Log directories
	{
		path:    "/logs/",
		name:    "Joomla Logs Directory",
		markers: [][]string{{"Index of", "Parent Directory", ".log"}},
		sev:     severity.Medium,
		desc:    "Joomla logs directory listing enabled, potentially exposing error logs with sensitive details",
	},
	{
		path:    "/administrator/logs/",
		name:    "Joomla Admin Logs Directory",
		markers: [][]string{{"Index of", "Parent Directory", ".log"}},
		sev:     severity.Medium,
		desc:    "Joomla administrator logs directory listing enabled",
	},
	// Temp directory
	{
		path:    "/tmp/",
		name:    "Joomla Temp Directory",
		markers: [][]string{{"Index of", "Parent Directory"}},
		sev:     severity.Medium,
		desc:    "Joomla temp directory listing enabled, potentially exposing temporary uploads and session data",
	},
	// Akeeba backup directories
	{
		path:    "/administrator/components/com_akeeba/backup/",
		name:    "Akeeba Backup Directory",
		markers: [][]string{{"Index of", "Parent Directory", ".jpa", ".zip"}},
		sev:     severity.Critical,
		desc:    "Akeeba backup directory exposed, containing full site backup archives with database dumps",
	},
	{
		path:    "/backups/",
		name:    "Backups Directory",
		markers: [][]string{{"Index of", "Parent Directory"}},
		sev:     severity.High,
		desc:    "Backups directory listing enabled, potentially exposing full site backup archives",
	},
	// Version disclosure via manifests — drop the bare "<version>" XML tag.
	{
		path:    "/administrator/manifests/files/joomla.xml",
		name:    "Joomla Version Manifest",
		markers: [][]string{{"files_joomla", "<name>Joomla"}},
		sev:     severity.Low,
		desc:    "Joomla version manifest exposed, revealing exact core version number",
	},
	{
		path:    "/language/en-GB/en-GB.xml",
		name:    "Joomla Language XML",
		markers: [][]string{{"<name>English"}, {"en-GB"}},
		sev:     severity.Info,
		desc:    "Joomla language XML exposed, potentially revealing version information",
	},
	// com_ajax info disclosure — require the full {success,message,data} envelope
	// shape, not a lone "data" key.
	{
		path:        "/index.php?option=com_ajax&format=json",
		name:        "Joomla com_ajax Disclosure",
		markers:     [][]string{{`"success"`}, {`"message"`}, {`"data"`}},
		antiMarkers: []string{"403 Forbidden"},
		sev:         severity.Low,
		desc:        "Joomla com_ajax endpoint publicly accessible, may expose plugin names or error details",
	},
	// Composer metadata — anchor on a Composer-specific key (+ the joomla vendor).
	{
		path:        "/composer.json",
		name:        "Composer JSON",
		markers:     [][]string{{`"require"`, `"autoload"`, `"require-dev"`}, {`"joomla"`, `"name"`, `"description"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer configuration exposed, revealing dependencies and internal package information",
	},
	{
		path:        "/composer.lock",
		name:        "Composer Lock",
		markers:     [][]string{{`"_readme"`, `"content-hash"`, `"packages"`}, {`"dist"`, `"reference"`, `"source"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer lock file exposed, revealing exact dependency versions for vulnerability mapping",
	},
	{
		path:        "/vendor/composer/installed.json",
		name:        "Vendor Installed JSON",
		markers:     [][]string{{`"dev-package-names"`, `"packages"`}, {`"version_normalized"`, `"install-path"`, `"dist"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Composer vendor installed.json exposed, revealing all installed packages with versions",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Joomla Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Joomla Misconfiguration module.
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
		ds: dedup.LazyDiskSet("joomla_misconfig"),
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

// ScanPerRequest probes the host for Joomla misconfiguration files.
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
			if result := m.probeFile(ctx, httpClient, p, base+p.path, fp); result != nil {
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
	randomPath := "/vigolium-joomla-404-" + utils.RandomString(8)

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

// probeFile sends a GET request for a Joomla file and validates the response.
func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
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
		if strings.Contains(strings.ToLower(location), "login") {
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

	// Require every marker group (Joomla/Composer-specific anchor + corroboration),
	// so a generic JSON envelope or XML tag cannot match on a single weak key, then
	// drop the finding if a nonexistent sibling under the same parent satisfies the
	// same groups (a sub-directory catch-all that 200s every child path). Root-level
	// probes are already covered by the random-path 404 fingerprint above.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, body, p.markers)
	if !ok {
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
			Name:        fmt.Sprintf("Joomla Misconfiguration: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"cms", "joomla", "misconfiguration"},
			Reference:   []string{"https://docs.joomla.org/Security_Checklist"},
		},
	}
}
