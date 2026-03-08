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
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// maxBodySize is the maximum response body size to scan (10MB).
const maxBodySize = 10 * 1024 * 1024

// batchEntry tracks a buffered response body for batch scanning.
type batchEntry struct {
	filename string // basename of the temp file within batchDir
	url      string
	host     string
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

	body := ctx.Response().Body()
	urlStr := ""
	host := ""
	if u, err := ctx.URL(); err == nil {
		urlStr = u.String()
		host = u.Host
	}

	// Write body to temp file with unique name
	seq := m.batchSeq.Add(1)
	filename := fmt.Sprintf("%d.txt", seq)
	if err := os.WriteFile(filepath.Join(dir, filename), body, 0600); err != nil {
		zap.L().Debug("Kingfisher: failed to buffer body", zap.Error(err))
		return nil, nil
	}

	m.batchMu.Lock()
	m.batchEntries = append(m.batchEntries, batchEntry{
		filename: filename,
		url:      urlStr,
		host:     host,
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

	var results []*output.ResultEvent
	for i := range result.Findings {
		f := &result.Findings[i]

		// Map finding back to the original URL via filename
		basename := filepath.Base(f.Finding.Path)
		entry, ok := entryByFile[basename]
		if !ok {
			continue
		}

		sev := severity.High
		conf := severity.Firm
		if f.IsValidated() {
			sev = severity.Critical
			conf = severity.Certain
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Info: output.Info{
				Name:        f.RuleName(),
				Description: "Leaked secret detected: " + f.RuleID(),
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"secret", "credential", "exposure"},
			},
			Host:             entry.host,
			URL:              entry.url,
			Matched:          entry.url,
			ExtractedResults: []string{redactSnippet(f.Snippet())},
			Metadata: map[string]any{
				"rule_id":   f.RuleID(),
				"rule_name": f.RuleName(),
				"validated": f.IsValidated(),
			},
		})
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

// redactSnippet shows first 8 and last 4 characters, masking the rest.
func redactSnippet(s string) string { return RedactSnippet(s) }

// RedactSnippet shows first 8 and last 4 characters, masking the rest.
func RedactSnippet(s string) string {
	if len(s) <= 16 {
		return strings.Repeat("*", len(s))
	}
	return s[:8] + strings.Repeat("*", len(s)-12) + s[len(s)-4:]
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
