package secret_detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"go.uber.org/zap"
)

// maxBodySize is the maximum response body size to scan (10MB).
const maxBodySize = 10 * 1024 * 1024

// batchEntry tracks a buffered response body for batch scanning.
type batchEntry struct {
	filename     string // basename of the temp file within batchDir
	url          string
	host         string
	statusCode   int    // response status — 3xx redirects downgrade secret severity
	headerValues string // joined response header values, for header-reflection downgrade
	respHead     string // raw response head (status line + headers, no body), for finding evidence
	request      string // raw request, for finding evidence and http_record linkage
}

// Module detects leaked secrets in HTTP response bodies using Kingfisher.
// Response bodies are buffered during scanning and batch-scanned at end-of-scan
// via the BatchFlusher interface for efficiency.
type Module struct {
	modkit.BasePassiveModule
	scannerOnce sync.Once
	scanner     *kingfisher.Scanner
	scannerErr  error

	// Batch scanning state
	batchDirOnce sync.Once
	batchDir     string
	batchDirErr  error
	batchMu      sync.Mutex
	batchSeq     atomic.Int64
	batchEntries []batchEntry
}

// New creates a new secret detection passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess filters out responses that are not worth scanning:
// nil/empty responses, media content, non-text MIME types, and oversized bodies.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}

	body := ctx.Response().Body()
	if len(body) == 0 || len(body) > maxBodySize {
		return false
	}

	mimeType := ctx.Response().Header("Content-Type")
	urlPath := ""
	if u, err := ctx.URL(); err == nil {
		urlPath = u.Path
	}

	if pkghttp.IsMediaContent(mimeType, urlPath) {
		return false
	}

	if !isTextBasedMIME(mimeType) {
		return false
	}

	return true
}

// ScanPerRequest buffers the response body for batch scanning at end-of-scan.
// Returns nil immediately — findings are produced by FlushFindings.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if _, err := m.getScanner(); err != nil {
		return nil, nil
	}

	dir, err := m.getBatchDir()
	if err != nil {
		return nil, nil
	}

	resp := ctx.Response()
	// A WAF/CDN edge block is the edge talking, not the application — skip it so a
	// challenge/error page's random tokens are never scanned as app secrets.
	if modkit.IsEdgeBlockedResponse(resp) {
		return nil, nil
	}
	body := resp.Body()
	urlStr := ""
	host := ""
	if u, err := ctx.URL(); err == nil {
		urlStr = u.String()
		host = u.Host
	}

	// Retain the response head (status line + headers, no body) and the raw
	// request so FlushFindings can attach human-readable evidence to each finding
	// without re-buffering the body in memory.
	respHead := string(resp.Head())
	request := ""
	if req := ctx.Request(); req != nil {
		request = string(req.Raw())
	}

	// Write body to temp file with unique name
	seq := m.batchSeq.Add(1)
	filename := fmt.Sprintf("%d.txt", seq)
	if err := os.WriteFile(filepath.Join(dir, filename), body, 0600); err != nil {
		zap.L().Debug("Kingfisher: failed to buffer body", zap.Error(err))
		return nil, nil
	}

	// Retain the status code and header values so FlushFindings can downgrade
	// matches that ride on a redirect or are merely reflected into a header
	// (e.g. an OAuth identifier in a Location URL bouncing to an SSO login).
	m.batchMu.Lock()
	m.batchEntries = append(m.batchEntries, batchEntry{
		filename:     filename,
		url:          urlStr,
		host:         host,
		statusCode:   resp.StatusCode(),
		headerValues: JoinHeaderValues(resp.Headers()),
		respHead:     respHead,
		request:      request,
	})
	m.batchMu.Unlock()

	return nil, nil
}

// FlushFindings batch-scans all buffered response bodies using a single
// kingfisher invocation and returns the collected findings.
func (m *Module) FlushFindings(_ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.batchMu.Lock()
	entries := m.batchEntries
	m.batchEntries = nil
	dir := m.batchDir
	m.batchMu.Unlock()

	// Clean up temp dir when done
	if dir != "" {
		defer func() { _ = os.RemoveAll(dir) }()
	}

	if len(entries) == 0 || dir == "" {
		return nil, nil
	}

	scanner, err := m.getScanner()
	if err != nil {
		return nil, nil
	}

	zap.L().Info("Kingfisher batch scan starting",
		zap.Int("buffered_responses", len(entries)))

	result, err := scanner.ScanDir(context.Background(), dir)
	if err != nil {
		zap.L().Warn("Kingfisher batch scan failed", zap.Error(err))
		return nil, nil
	}

	if !result.HasFindings() {
		zap.L().Info("Kingfisher batch scan: no findings")
		return nil, nil
	}

	// Build filename→entry lookup
	entryByFile := make(map[string]*batchEntry, len(entries))
	for i := range entries {
		entryByFile[entries[i].filename] = &entries[i]
	}

	// Cache bodies read back from the temp dir so a file with several secrets is
	// read only once.
	bodyByFile := make(map[string][]byte)

	var results []*output.ResultEvent
	for i := range result.Findings {
		f := &result.Findings[i]

		// Map finding back to the original URL via filename
		basename := filepath.Base(f.Finding.Path)
		entry, ok := entryByFile[basename]
		if !ok {
			continue
		}

		// Read the body back from the temp file it was buffered to (caching per
		// file) — needed both for the blob guard below and to reconstruct the
		// finding's evidence response.
		body, cached := bodyByFile[basename]
		if !cached {
			body, _ = os.ReadFile(filepath.Join(dir, basename))
			bodyByFile[basename] = body
		}

		// A match buried inside a long base64 run is a chunk of encoded binary
		// (an inline data: URI image / asset blob), not a real secret — drop it
		// before it becomes a finding. This kills the common "32-char token rule
		// hits inside an inline image on an error page" false positive.
		if IsBinaryBlobMatch(body, f.Snippet()) {
			continue
		}

		sev, conf := SecretFindingSeverity(
			f.IsValidated(),
			IsRedirectStatus(entry.statusCode),
			SnippetInHeaderValues(f.Snippet(), entry.headerValues),
			LowValueJWT(f.Snippet()),
			IsReCaptchaSiteKey(f.RuleName()),
			IsGoogleAPIKey(f.RuleName(), f.Snippet()),
		)

		// Reconstruct the matched response (head + full-or-windowed body) so the
		// finding shows the actual leak in context.
		response := BuildEvidenceResponse(entry.respHead, body, f.Snippet(), f.Finding.Line)

		event := NewSecretFinding(f, sev, conf, entry.host, entry.url, entry.request, response)
		event.ModuleID = ModuleID
		results = append(results, event)
	}

	zap.L().Info("Kingfisher batch scan completed",
		zap.Int("findings", len(results)),
		zap.Duration("duration", result.ScanDuration))

	return results, nil
}

// getBatchDir lazily creates the temp directory for buffering response bodies.
func (m *Module) getBatchDir() (string, error) {
	m.batchDirOnce.Do(func() {
		m.batchDir, m.batchDirErr = os.MkdirTemp("", "kingfisher-batch-*")
	})
	return m.batchDir, m.batchDirErr
}

// getScanner returns the lazily-initialized Kingfisher scanner.
func (m *Module) getScanner() (*kingfisher.Scanner, error) {
	m.scannerOnce.Do(func() {
		m.scanner, m.scannerErr = kingfisher.NewScanner(nil)
		if m.scannerErr == nil {
			m.scannerErr = m.scanner.EnsureBinary(context.Background())
		}
	})
	return m.scanner, m.scannerErr
}

// isTextBasedMIME checks if the MIME type indicates text-based content.
func isTextBasedMIME(mimeType string) bool { return IsTextBasedMIME(mimeType) }

// IsTextBasedMIME checks if the MIME type indicates text-based content.
func IsTextBasedMIME(mimeType string) bool {
	if mimeType == "" {
		return true
	}
	mt := strings.ToLower(mimeType)
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	textTypes := []string{
		"/json",
		"/javascript",
		"/x-javascript",
		"/xml",
		"/x-yaml",
		"/yaml",
	}
	for _, t := range textTypes {
		if strings.Contains(mt, t) {
			return true
		}
	}
	return strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}
