package sensitive_file_discovery

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// envAssignmentPattern matches a genuine dotenv KEY=VALUE assignment line
// (uppercase env-style key at line start, optionally `export`-prefixed). It
// gates the Critical .env findings: a bare "=" marker matched any non-HTML body
// (JSON, CSS, config) that happened to contain an equals sign.
var envAssignmentPattern = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]+[ \t]*=`)

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Sensitive File Discovery active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Sensitive File Discovery module.
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
		ds: dedup.LazyDiskSet("sensitive_file_discovery"),
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

// ScanPerRequest probes the host for sensitive files.
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

	// Walk the web root plus every observed path prefix — INCLUDING static/asset
	// and CDN-style directories (/assets, /static, ...), where a misconfigured
	// server or object-storage front may serve an exposed .env/.git/backup that a
	// root-only probe never reaches. Claim each (host, base) pair up front so a
	// fully-deduped request issues no traffic, including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePathsIncludingStatic(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}
	// Generic content-type probing is root-only and runs once per host — only when
	// the root base "" was unclaimed in this batch (it is always first when present).
	probeRoot := bases[0] == ""

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent

	// Marker-based sensitive files: probed under every candidate base path so a
	// /<context>/.git/config or /assets/.env is found, not only the web root.
	for _, base := range bases {
		for _, sf := range sensitiveFiles {
			result := m.probeFile(ctx, httpClient, scanCtx, sf, base+sf.path, fp)
			if result != nil {
				results = append(results, result)
			}
		}
	}

	// Generic file probing (content-type + body differencing) stays root-anchored
	// and runs once per host — only when the root base was first claimed in this
	// batch. Skip if 404 fingerprinting failed or if the 404 page itself returns
	// text/plain or octet-stream (we can't distinguish real files).
	if probeRoot && fp != nil {
		fpCT := fp.contentType
		if !strings.Contains(fpCT, "text/plain") && !strings.Contains(fpCT, "application/octet-stream") {
			for _, cat := range genericFileCategories {
				for _, path := range cat.paths {
					result := m.probeGenericFile(ctx, httpClient, path, cat.name, cat.desc, fp)
					if result != nil {
						results = append(results, result)
					}
				}
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
	randomPath := "/vigolium-404-check-" + utils.RandomString(8)

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

// confirms reports whether body is a genuine match for sf: no anti-marker is
// present, at least one exact content marker matches, and — for a .env file — a
// real KEY=VALUE assignment line exists (the credential markers DB_/SECRET/… only
// corroborate; prose mentioning "SECRET" must not forge a Critical finding). It
// is the single source of truth used by all three confirmation rounds and the
// decoy-baseline check, so they stay consistent. matched carries the evidence
// substrings; ok is false (and matched nil) when the body is not a real match.
func (sf sensitiveFile) confirms(body string) (matched []string, ok bool) {
	for _, anti := range sf.antiMarkers {
		if strings.Contains(body, anti) {
			return nil, false
		}
	}
	// Strip the reflected probe path before marker matching so a marker that is
	// also the path slug (e.g. "draft" for /api/draft, "preview" for /api/preview)
	// cannot match on a page that merely echoes the requested URL into an href,
	// breadcrumb, or JSON "path" field. Content-signature markers (KEY names, JSON
	// keys) are unaffected — they don't appear inside the probe path.
	matchBody := modkit.StripReflectedProbePath(body, sf.path)
	for _, marker := range sf.markers {
		if strings.Contains(matchBody, marker) {
			matched = append(matched, marker)
		}
	}
	if strings.HasPrefix(sf.path, "/.env") {
		if !envAssignmentPattern.MatchString(body) {
			return nil, false
		}
		if len(matched) == 0 {
			matched = append(matched, "env assignment (KEY=VALUE)")
		}
		return matched, true
	}
	return matched, len(matched) > 0
}

// probeFile sends a GET request for a sensitive file and validates the response.
func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	sf sensitiveFile,
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

	// Round 1 — content confirmation: status 200, no anti-marker, an exact content
	// marker present (.env gated on a real KEY=VALUE assignment line).
	if status != 200 {
		return nil
	}
	matchedMarkers, ok := sf.confirms(body)
	if !ok {
		return nil
	}

	// Round 2 — reproduce: re-fetch the same path with the response cache bypassed.
	// The body must stay a confirmed match AND remain textually stable, so a
	// random / load-balanced / one-shot 200 cannot forge a finding.
	repStatus, repBody, repOK := modkit.FetchPath(ctx, httpClient, probePath)
	if !repOK || repStatus != 200 || !modkit.BodiesSimilar(body, repBody) {
		return nil
	}
	if _, ok := sf.confirms(repBody); !ok {
		return nil
	}

	// Round 3 — decoy baseline: a same-extension random sibling under the same
	// directory must NOT return a body equivalent to the candidate, and must not
	// itself satisfy the markers. This subtracts sub-directory catch-alls (a SPA
	// fallback, a logging proxy, an object-store wildcard) that serve identical
	// content for every <dir>/*.<ext> — the "/orders/run.log equals
	// /orders/<random>.log" false positive.
	if decoyStatus, decoyBody, served := modkit.DecoyFileBaseline(scanCtx, ctx, httpClient, probePath); served && decoyStatus == status {
		if modkit.BodiesSimilar(body, decoyBody) {
			return nil
		}
		if _, ok := sf.confirms(decoyBody); ok {
			return nil
		}
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
			Name:        fmt.Sprintf("Sensitive File: %s", sf.name),
			Description: sf.desc,
			Severity:    modkit.CapSeverity(sf.sev, severity.Medium),
			Confidence:  ModuleConfidence,
			Tags:        []string{"sensitive-file", "information-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
		},
	}
}

// probeGenericFile sends a GET request and validates using content-type and body
// differencing (BCheck-style validation) rather than specific content markers.
func (m *Module) probeGenericFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	categoryName string,
	categoryDesc string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
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

	// 1. Status 200 required
	if resp.Response().StatusCode != 200 {
		return nil
	}

	// 2. Content-Type must contain text/plain or application/octet-stream
	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "application/octet-stream") {
		return nil
	}

	body := resp.Body().String()

	// 8. Body must not be empty
	if len(strings.TrimSpace(body)) == 0 {
		return nil
	}

	// 4-5. Body must differ from 404 fingerprint
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

	// 6. No HTML tags
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<head") || strings.Contains(lower, "<body") {
		return nil
	}

	// 7. No false positive strings
	for _, fpStr := range genericFalsePositives {
		if strings.Contains(lower, fpStr) {
			return nil
		}
	}

	// Extract filename from path
	filename := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		filename = path[idx+1:]
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + path

	return &output.ResultEvent{
		URL:      targetURL,
		Matched:  targetURL,
		Request:  string(modifiedRaw),
		Response: resp.FullResponseString(),
		Info: output.Info{
			Name:        fmt.Sprintf("Exposed %s: %s", categoryName, filename),
			Description: categoryDesc,
			Severity:    severity.Low,
			Confidence:  severity.Tentative,
			Tags:        []string{"sensitive-file", "information-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
		},
	}
}
