package backup_file_discovery

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
	var results []*output.ResultEvent

	for _, path := range paths {
		result := m.probePath(ctx, httpClient, path, fp)
		if result != nil {
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

	// Validation differs for SQL/text dumps vs binary archives
	confidence := severity.Tentative
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
		confidence = severity.Firm
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

		// Additional signal: Content-Disposition header
		cd := strings.ToLower(resp.Response().Header.Get("Content-Disposition"))
		if strings.Contains(cd, "attachment") {
			confidence = severity.Firm
		}
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
			Severity:    severity.High,
			Confidence:  confidence,
			Tags:        []string{"backup-file", "information-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
		},
	}
}
