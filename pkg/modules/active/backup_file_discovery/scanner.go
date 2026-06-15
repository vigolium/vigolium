package backup_file_discovery

import (
	"bytes"
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

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Backup File Discovery active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Backup File Discovery module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("backup_file_discovery"),
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

// maxBackupContextBases caps how many base paths the backup walk probes (the web
// root plus the shallowest context-path prefix). It is deliberately small:
// generatePaths already emits hundreds of hostname-derived candidates, so each
// extra base multiplies request volume.
const maxBackupContextBases = 2

// ScanPerHost probes the host for backup files.
func (m *Module) ScanPerHost(
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

	paths := generatePaths(host)

	// Probe the web root plus the shallowest non-static context-path prefix of the
	// observed request (e.g. /app), so a backup dropped inside an app mounted under
	// a sub-path is found too. Bounded to maxBackupContextBases: generatePaths
	// already yields hundreds of hostname-derived candidates, so a wider walk would
	// multiply request volume far beyond how webroot backups are typically laid out.
	bases := []string{""}
	if urlx, err := ctx.URL(); err == nil {
		if cb := modkit.CandidateBasePaths(urlx.Path); len(cb) >= maxBackupContextBases {
			bases = cb[:maxBackupContextBases]
		}
	}

	var results []*output.ResultEvent

	for _, base := range bases {
		for _, path := range paths {
			result := m.probePath(ctx, httpClient, scanCtx, base+path, fp)
			if result != nil {
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
	randomPath := "/vigolium-bkp-404-" + utils.RandomString(8) + ".zip"

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

// archiveContentTypes are Content-Type values that indicate binary archive responses.
var archiveContentTypes = []string{
	"application/zip",
	"application/x-zip-compressed",
	"application/gzip",
	"application/x-gzip",
	"application/x-tar",
	"application/x-bzip2",
	"application/x-7z-compressed",
	"application/x-rar-compressed",
	"application/vnd.rar",
	"application/octet-stream",
}

// sqlMarkers are content strings that indicate a real SQL dump.
var sqlMarkers = []string{
	"CREATE TABLE", "INSERT INTO", "DROP TABLE",
	"ALTER TABLE", "CREATE DATABASE", "-- MySQL dump",
	"-- PostgreSQL database dump", "BEGIN TRANSACTION",
	"PRAGMA", "sqlite",
}

// hasArchiveMagic reports whether the response body begins with a recognized
// binary-archive signature. A genuine archive starts with one of these magic
// byte sequences; a catch-all / error 200 served as application/octet-stream (a
// common false-positive source) will not. This is the binary-archive equivalent
// of the SQL content markers.
func hasArchiveMagic(body string) bool {
	b := []byte(body)
	signatures := [][]byte{
		{0x50, 0x4B, 0x03, 0x04},             // zip / jar / docx (local file header)
		{0x50, 0x4B, 0x05, 0x06},             // empty zip (end of central directory)
		{0x1F, 0x8B},                         // gzip
		{0x42, 0x5A, 0x68},                   // bzip2 ("BZh")
		{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, // 7z
		{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, // rar ("Rar!\x1a\x07")
		{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, // xz
	}
	for _, sig := range signatures {
		if bytes.HasPrefix(b, sig) {
			return true
		}
	}
	// POSIX tar: the "ustar" magic lives at byte offset 257.
	if len(b) >= 262 && string(b[257:262]) == "ustar" {
		return true
	}
	return false
}

// isSQLExtension returns true if the path ends with an SQL/dump-related extension.
func isSQLExtension(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".sql") ||
		strings.HasSuffix(lower, ".dump") ||
		strings.HasSuffix(lower, ".dump.sql") ||
		strings.HasSuffix(lower, ".db") ||
		strings.HasSuffix(lower, ".sqlite")
}

// probePath sends a GET request for a backup file path and validates the response.
func (m *Module) probePath(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	path string,
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

	status := resp.Response().StatusCode

	// Only accept 200
	if status != 200 {
		return nil
	}

	body := resp.Body().String()
	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))

	// Check against 404 fingerprint
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

	// Anti-markers: skip HTML error pages masquerading as 200
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<html") {
		return nil
	}

	// Minimum size: backup files should be >1KB
	if len(body) < 1024 {
		return nil
	}

	// Validation differs for SQL/text dumps vs binary archives. Findings are
	// reported at the capped Medium / Tentative level shared by the sensitive-file
	// family regardless of how strongly the archive validates.
	if isSQLExtension(path) {
		// SQL dumps: require at least one marker
		matched := false
		for _, marker := range sqlMarkers {
			if strings.Contains(body, marker) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	} else {
		// Binary archives: validate Content-Type
		validCT := false
		for _, act := range archiveContentTypes {
			if strings.Contains(ct, act) {
				validCT = true
				break
			}
		}
		if !validCT {
			return nil
		}

		// Strict drop-on-fail: require the body to actually begin with a known
		// archive magic signature. An archive Content-Type alone is trivially
		// spoofed by a catch-all / error 200 served as octet-stream; the magic
		// bytes are the real content marker for a binary archive.
		if !hasArchiveMagic(body) {
			return nil
		}
	}

	// Soft-404 / SPA-shell gate: reject a 200 that is just the host's wildcard
	// response to a random path.
	location := resp.Response().Header.Get("Location")
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, status, []byte(body), location) {
		return nil
	}

	// Round 2 — reproduce: re-fetch the same path with the cache bypassed; it must
	// still return a 200 whose body is textually stable, so a one-shot or flapping
	// response cannot forge a finding.
	if repStatus, repBody, repOK := modkit.FetchPath(ctx, httpClient, path); !repOK || repStatus != 200 || !modkit.BodiesSimilar(body, repBody) {
		return nil
	}

	// Round 3 — decoy baseline: a same-extension random sibling under the same
	// directory must NOT return an equivalent body. ConfirmNotSoft404 above probes
	// a no-extension random path and so cannot see an extension-scoped catch-all (a
	// wildcard that hands back the same archive/dump for every *.zip / *.sql); the
	// same-extension decoy can.
	if decoyStatus, decoyBody, served := modkit.DecoyFileBaseline(scanCtx, ctx, httpClient, path); served && decoyStatus == status && modkit.BodiesSimilar(body, decoyBody) {
		return nil
	}

	// Extract filename from path for display
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
			Name:        fmt.Sprintf("Backup File Exposed: %s", filename),
			Description: fmt.Sprintf("Publicly accessible backup file found at %s. Backup archives may contain source code, database dumps, credentials, or other sensitive data.", path),
			Severity:    severity.Medium,
			Confidence:  severity.Tentative,
			Tags:        []string{"backup-file", "information-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
		},
	}
}
