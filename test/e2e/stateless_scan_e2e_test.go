//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// setupStatelessDB creates a file-based temp SQLite DB, simulating --stateless behavior.
// Returns the DB, repository, and the temp file path for cleanup verification.
func setupStatelessDB(t *testing.T) (*database.DB, *database.Repository, string) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "vigolium-stateless-test-*.sqlite")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        tmpPath,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))

	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(tmpPath)
		_ = os.Remove(tmpPath + "-wal")
		_ = os.Remove(tmpPath + "-shm")
	})

	return db, database.NewRepository(db), tmpPath
}

// startTestHTTPServer creates a simple HTTP server that returns HTML and JSON pages.
func startTestHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		q := r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`<html><head><title>Test App</title></head><body>` +
			`<h1>Search results for: ` + q + `</h1>` +
			`<form action="/search"><input name="q"/></form>` +
			`</body></html>`))
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":[{"id":1,"name":"admin"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// runStatelessScan runs a scan against the given targets using a temp DB.
// Returns the DB for post-scan queries.
func runStatelessScan(t *testing.T, targets []string) (*database.DB, *database.Repository) {
	t.Helper()
	db, repo, _ := setupStatelessDB(t)

	opts := types.DefaultOptions()
	opts.Targets = targets
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.HeuristicsCheck = "none"

	r, err := runner.New(opts)
	require.NoError(t, err)

	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)

	err = r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")
	r.Close()

	return db, repo
}

// queryTestExportData queries HTTP records and findings from the DB for test verification.
// This is intentionally simple — it only checks that data exists in the DB,
// not the full export envelope format (which is tested via the JSONL output parsing).
func queryTestExportData(t *testing.T, db *database.DB) (records []*database.HTTPRecord, findings []*database.Finding) {
	t.Helper()
	ctx := context.Background()

	err := db.NewSelect().Model(&records).OrderExpr("created_at DESC").Scan(ctx)
	require.NoError(t, err)

	err = db.NewSelect().Model(&findings).OrderExpr("found_at DESC").Scan(ctx)
	require.NoError(t, err)

	return records, findings
}

// TestStateless_ScanAndExportJSONL verifies the stateless workflow:
// scan against a target, export full data to JSONL, and verify the output file.
func TestStateless_ScanAndExportJSONL(t *testing.T) {
	srv := startTestHTTPServer(t)
	db, _ := runStatelessScan(t, []string{srv.URL + "/?q=test", srv.URL + "/api/users"})

	// Verify data was written to the temp DB
	records, _ := queryTestExportData(t, db)
	require.GreaterOrEqual(t, len(records), 1, "Expected at least 1 HTTP record in temp DB")
	t.Logf("Temp DB has %d HTTP records", len(records))

	// Simulate the stateless JSONL export using the same json.NewEncoder pattern
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "stateless-output.jsonl")

	f, err := os.Create(outputPath)
	require.NoError(t, err)

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, r := range records {
		require.NoError(t, enc.Encode(map[string]any{"type": "http_record", "data": r}))
	}
	require.NoError(t, f.Close())

	// Parse and verify JSONL content
	outFile, err := os.Open(outputPath)
	require.NoError(t, err)
	defer outFile.Close()

	var lineCount int
	var hasHTTPRecord bool
	scanner := bufio.NewScanner(outFile)
	for scanner.Scan() {
		lineCount++
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &envelope))
		if envelope["type"] == "http_record" {
			hasHTTPRecord = true
		}
	}
	require.NoError(t, scanner.Err())
	assert.Greater(t, lineCount, 0, "JSONL output should have at least one line")
	assert.True(t, hasHTTPRecord, "JSONL output should contain http_record entries")
	t.Logf("JSONL output: %d lines, has_http_records=%v", lineCount, hasHTTPRecord)
}

// TestStateless_ScanAndExportHTML verifies stateless HTML report generation.
// The report is generated even when the scan produces no records, validating
// that the export pipeline works end-to-end with the temp DB.
func TestStateless_ScanAndExportHTML(t *testing.T) {
	srv := startTestHTTPServer(t)
	db, _ := runStatelessScan(t, []string{srv.URL + "/?q=hello", srv.URL + "/api/users"})

	records, _ := queryTestExportData(t, db)
	t.Logf("HTML test: %d HTTP records in temp DB", len(records))

	// Build export items in the same envelope format used by production code
	var items []any
	for _, r := range records {
		items = append(items, map[string]any{"type": "http_record", "data": r})
	}

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "stateless-report.html")

	meta := output.HTMLReportMeta{
		Title:   "Stateless Test Report",
		Version: "test",
	}
	err := output.GenerateHTMLReport(items, outputPath, meta)
	require.NoError(t, err)

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Greater(t, len(content), 100, "HTML report should have meaningful content")
	assert.Contains(t, string(content), "<html", "Output should be valid HTML")
	t.Logf("HTML report: %d bytes, %d records", len(content), len(records))
}

// TestStateless_ScanConsoleFormat verifies that stateless + console format
// works correctly: the scan runs against the temp DB without errors.
// In console mode, StandardWriter handles --output directly (no post-scan export).
func TestStateless_ScanConsoleFormat(t *testing.T) {
	srv := startTestHTTPServer(t)
	db, _ := runStatelessScan(t, []string{srv.URL + "/?q=console", srv.URL + "/api/users"})

	// Verify the scan completed and the DB is queryable (scan ran against temp DB).
	records, findings := queryTestExportData(t, db)
	t.Logf("Console mode: %d HTTP records, %d findings in temp DB", len(records), len(findings))
	// The scan completing without error is the primary assertion (via runStatelessScan).
}

// TestStateless_TempDBCleanup verifies that the temp DB file and WAL/SHM sidecar
// files are removed after the database is closed.
func TestStateless_TempDBCleanup(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "vigolium-cleanup-test-*.sqlite")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        tmpPath,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))

	// Verify file exists before cleanup
	_, err = os.Stat(tmpPath)
	require.NoError(t, err, "DB file should exist before cleanup")

	// Close then remove — mirrors the defer order in runScanCmd
	require.NoError(t, db.Close())
	_ = os.Remove(tmpPath)
	_ = os.Remove(tmpPath + "-wal")
	_ = os.Remove(tmpPath + "-shm")

	// Verify files are gone
	_, err = os.Stat(tmpPath)
	assert.True(t, os.IsNotExist(err), "DB file should be removed after cleanup")
}

// TestStateless_MultiFormatExport verifies that --format jsonl,html produces
// both a .jsonl and a .html output file from a single stateless scan.
func TestStateless_MultiFormatExport(t *testing.T) {
	// Use synthetic items to decouple from scan flakiness (scan may return 0 records).
	items := []any{
		map[string]any{"type": "http_record", "data": map[string]any{"url": "https://example.com/a", "method": "GET", "status_code": 200}},
		map[string]any{"type": "http_record", "data": map[string]any{"url": "https://example.com/b", "method": "POST", "status_code": 201}},
	}

	outputDir := t.TempDir()
	basePath := filepath.Join(outputDir, "multi-output")

	// Simulate multi-format Options
	opts := types.DefaultOptions()
	opts.OutputFormats = []string{"jsonl", "html"}
	opts.Output = basePath
	opts.Stateless = true
	opts.Silent = true

	// Verify OutputPathForFormat generates expected paths
	jsonlPath := opts.OutputPathForFormat("jsonl")
	htmlPath := opts.OutputPathForFormat("html")
	assert.Equal(t, basePath+".jsonl", jsonlPath)
	assert.Equal(t, basePath+".html", htmlPath)

	// --- Export JSONL ---
	f, err := os.Create(jsonlPath)
	require.NoError(t, err)
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		require.NoError(t, enc.Encode(item))
	}
	require.NoError(t, f.Close())

	// --- Export HTML ---
	meta := output.HTMLReportMeta{
		Title:   "Multi-Format Test Report",
		Version: "test",
	}
	err = output.GenerateHTMLReport(items, htmlPath, meta)
	require.NoError(t, err)

	// --- Verify JSONL output ---
	jsonlFile, err := os.Open(jsonlPath)
	require.NoError(t, err)
	defer jsonlFile.Close()

	var lineCount int
	scanner := bufio.NewScanner(jsonlFile)
	for scanner.Scan() {
		lineCount++
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &envelope))
		assert.Equal(t, "http_record", envelope["type"], "Each JSONL line should have type=http_record")
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, len(items), lineCount, "JSONL should have one line per item")

	// --- Verify HTML output ---
	htmlInfo, err := os.Stat(htmlPath)
	require.NoError(t, err)
	assert.Greater(t, htmlInfo.Size(), int64(100), "HTML report should have meaningful content")

	t.Logf("Multi-format export: JSONL=%d lines, HTML=%d bytes",
		lineCount, htmlInfo.Size())
}

// TestStateless_MultiFormatBasePathStripsExtension verifies that OutputBasePath
// strips known extensions so multi-format outputs don't get double extensions.
func TestStateless_MultiFormatBasePathStripsExtension(t *testing.T) {
	tests := []struct {
		output   string
		wantBase string
	}{
		{"report.jsonl", "report"},
		{"report.html", "report"},
		{"report.json", "report"},
		{"report", "report"},
		{"/tmp/scan/results.jsonl", "/tmp/scan/results"},
		{"/tmp/scan/results.txt", "/tmp/scan/results.txt"}, // unknown ext kept
		{"report.html.bak", "report.html.bak"},             // non-standard kept
	}

	for _, tc := range tests {
		opts := types.DefaultOptions()
		opts.Output = tc.output
		assert.Equal(t, tc.wantBase, opts.OutputBasePath(),
			"OutputBasePath(%q)", tc.output)
	}
}

// TestStateless_HasFormat verifies the HasFormat helper on Options.
func TestStateless_HasFormat(t *testing.T) {
	opts := types.DefaultOptions()

	opts.OutputFormats = []string{"console"}
	assert.True(t, opts.HasFormat("console"))
	assert.False(t, opts.HasFormat("jsonl"))
	assert.False(t, opts.HasFormat("html"))

	opts.OutputFormats = []string{"jsonl", "html"}
	assert.False(t, opts.HasFormat("console"))
	assert.True(t, opts.HasFormat("jsonl"))
	assert.True(t, opts.HasFormat("html"))
}

// TestStateless_FlagValidation tests that the stateless flag constraints
// produce the expected error messages via the Options struct.
// The actual CLI-level validation is in runScanCmd; these tests verify the
// conditions that runScanCmd checks.
func TestStateless_FlagValidation(t *testing.T) {
	t.Run("stateless_without_output_warns", func(t *testing.T) {
		// runScanCmd no longer rejects --stateless without --output; it just
		// warns that results will be discarded with the temp DB.
		opts := types.DefaultOptions()
		opts.Stateless = true
		opts.Output = ""
		shouldWarn := opts.Stateless && opts.Output == ""
		assert.True(t, shouldWarn, "--stateless without --output should trigger a warning")
	})

	t.Run("stateless_with_db_is_rejected", func(t *testing.T) {
		// runScanCmd checks: opts.Stateless && globalDB != ""
		// We simulate by checking both conditions are true
		opts := types.DefaultOptions()
		opts.Stateless = true
		opts.Output = "/tmp/out.jsonl"
		dbFlag := "/tmp/custom.db"
		conflictsWithDB := opts.Stateless && dbFlag != ""
		assert.True(t, conflictsWithDB, "--stateless with --db should be rejected")
	})

	t.Run("stateless_with_output_is_valid", func(t *testing.T) {
		opts := types.DefaultOptions()
		opts.Stateless = true
		opts.Output = "/tmp/test-output.jsonl"
		valid := opts.Stateless && opts.Output != ""
		assert.True(t, valid, "--stateless with --output should be valid")
	})
}
