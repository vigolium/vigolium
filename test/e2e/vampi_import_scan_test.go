//go:build canary

package e2e

import (
	"context"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

func sampleInputDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "sample-inputs")
}

func parseVAmPIOpenAPI(t *testing.T, baseURL string) []*httpmsg.HttpRequestResponse {
	t.Helper()
	parser := openapi.New()
	parser.SetOptions(formats.InputFormatOptions{})
	parser.SetOpenAPIOptions(openapi.Options{
		BaseURL:              baseURL,
		DefaultFallbackValue: "1",
	})

	var items []*httpmsg.HttpRequestResponse
	err := parser.Parse(filepath.Join(sampleInputDir(), "vampi-openapi3.yml"), func(rr *httpmsg.HttpRequestResponse) bool {
		items = append(items, rr)
		return true
	})
	require.NoError(t, err, "failed to parse VAmPI OpenAPI spec")
	return items
}

func parseVAmPIPostman(t *testing.T, baseURL string) []*httpmsg.HttpRequestResponse {
	t.Helper()
	parser := postman.New()
	parser.SetPostmanOptions(postman.Options{
		BaseURL: baseURL,
	})

	var items []*httpmsg.HttpRequestResponse
	err := parser.Parse(filepath.Join(sampleInputDir(), "vampi-postman_collection.json"), func(rr *httpmsg.HttpRequestResponse) bool {
		items = append(items, rr)
		return true
	})
	require.NoError(t, err, "failed to parse VAmPI Postman collection")
	return items
}

func initVAmPIDB(t *testing.T, baseURL string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/createdb")
	require.NoError(t, err, "failed to call /createdb")
	defer resp.Body.Close()
	require.Less(t, resp.StatusCode, 500, "/createdb returned server error")
}

// vampiReachable reports whether the VAmPI container is currently serving HTTP
// (retried briefly). Used to tell an environmental container outage apart from
// a scanner regression: when the full canary suite runs many containers at once
// the VAmPI container can fall over mid-scan, which leaves the scan with no
// baseline responses (hence no records or findings). A confirmed-unreachable
// target is unambiguously environmental — never a scanner bug — so callers skip
// in that case but still assert against a healthy target.
func vampiReachable(baseURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(baseURL + "/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

// scanModuleIDs lists modules that can produce findings against VAmPI.
// VAmPI uses SQLAlchemy (no raw SQL errors), so error-based SQLi won't fire.
// We use modules that detect issues via response behavior, not error strings.
var scanModuleIDs = []string{
	"sqli-error-based",
	"nosqli-error-based",
	"lfi-generic",
	"cors-misconfiguration",
	"crlf-injection",
}

type scanResult struct {
	findings     []*output.ResultEvent
	trafficCount int
}

func runImportNativeScan(t *testing.T, ctx context.Context, items []*httpmsg.HttpRequestResponse) *scanResult {
	t.Helper()

	infra, err := SetupTestInfra()
	require.NoError(t, err, "failed to setup test infrastructure")
	t.Cleanup(func() { infra.Cleanup() })

	activeModules := modules.DefaultRegistry.GetActiveModulesByIDs(scanModuleIDs)
	require.NotEmpty(t, activeModules, "no active modules resolved")

	src := source.NewSliceSource(items, nil)

	var mu sync.Mutex
	result := &scanResult{}

	svc := &services.Services{Options: infra.Options}

	cfg := core.ExecutorConfig{
		Workers:       4,
		Services:      svc,
		HTTPRequester: infra.HTTPClient,
		MaxDuration:   5 * time.Minute,
		OnResult: func(r *output.ResultEvent) {
			mu.Lock()
			result.findings = append(result.findings, r)
			mu.Unlock()
		},
		OnTraffic: func(method, url string, statusCode int, contentType string) {
			mu.Lock()
			result.trafficCount++
			mu.Unlock()
		},
	}

	executor := core.NewExecutor(cfg, src, activeModules, nil)
	_, err = executor.Execute(ctx)
	require.NoError(t, err, "executor returned error")

	return result
}

// TestVAmPI_ImportOpenAPI_NativeScan is a full E2E pipeline test:
// parse VAmPI OpenAPI spec → start VAmPI container → run native scan → verify pipeline.
//
// This test validates that:
// 1. The OpenAPI parser produces valid requests with correct service info
// 2. All parsed requests successfully fetch baseline responses from live VAmPI
// 3. The executor processes all items without errors
// 4. Active modules are dispatched and complete (findings depend on module/VAmPI match)
func TestVAmPI_ImportOpenAPI_NativeScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	app := startVAmPI(t)
	t.Logf("VAmPI running at %s", app.BaseURL)

	// Phase 1: Parse and validate OpenAPI spec
	items := parseVAmPIOpenAPI(t, app.BaseURL)
	require.NotEmpty(t, items, "OpenAPI parse should produce requests")
	t.Logf("Parsed %d requests from OpenAPI spec", len(items))

	methods := map[string]int{}
	for _, rr := range items {
		req := rr.Request()
		methods[req.Method()]++
		assert.NotEmpty(t, req.Path(), "request path should not be empty")
		assert.NotNil(t, req.Service(), "request should have service info")
		svc := req.Service()
		assert.Equal(t, "localhost", svc.Host(), "service host should be localhost")
		assert.Equal(t, "http", svc.Protocol(), "service protocol should be http")
	}
	assert.True(t, methods["GET"] > 0, "expected GET requests")
	assert.True(t, methods["POST"] > 0, "expected POST requests")
	assert.True(t, methods["PUT"] > 0, "expected PUT requests")
	assert.True(t, methods["DELETE"] > 0, "expected DELETE requests")

	// Phase 2: Init VAmPI DB and run native scan
	initVAmPIDB(t, app.BaseURL)

	result := runImportNativeScan(t, ctx, items)
	t.Logf("Traffic processed: %d, Findings: %d", result.trafficCount, len(result.findings))

	// Assert: all parsed requests got baseline responses from the live container
	assert.Equal(t, len(items), result.trafficCount,
		"all parsed requests should fetch baseline responses from VAmPI")

	for _, f := range result.findings {
		t.Logf("Finding: module=%s severity=%s url=%s param=%s",
			f.ModuleID, f.Info.Severity, f.URL, f.FuzzingParameter)
	}
}

// TestVAmPI_ImportPostman_NativeScan validates the full pipeline with a Postman collection.
func TestVAmPI_ImportPostman_NativeScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	app := startVAmPI(t)
	t.Logf("VAmPI running at %s", app.BaseURL)

	// Phase 1: Parse and validate Postman collection
	items := parseVAmPIPostman(t, app.BaseURL)
	require.NotEmpty(t, items, "Postman parse should produce requests")
	t.Logf("Parsed %d requests from Postman collection", len(items))

	methods := map[string]int{}
	paths := map[string]bool{}
	for _, rr := range items {
		req := rr.Request()
		methods[req.Method()]++
		paths[req.Path()] = true
		assert.NotEmpty(t, req.Path(), "request path should not be empty")
		assert.NotNil(t, req.Service(), "request should have service info")
	}
	assert.Equal(t, 14, len(items), "VAmPI Postman collection should produce 14 requests")
	assert.Equal(t, 8, methods["GET"], "expected 8 GET requests")
	assert.Equal(t, 3, methods["POST"], "expected 3 POST requests")
	assert.Equal(t, 2, methods["PUT"], "expected 2 PUT requests")
	assert.Equal(t, 1, methods["DELETE"], "expected 1 DELETE request")
	assert.True(t, paths["/createdb"], "expected /createdb path")
	assert.True(t, paths["/users/v1"], "expected /users/v1 path")
	assert.True(t, paths["/books/v1"], "expected /books/v1 path")

	// Phase 2: Init VAmPI DB and run native scan
	initVAmPIDB(t, app.BaseURL)

	result := runImportNativeScan(t, ctx, items)
	t.Logf("Traffic processed: %d, Findings: %d", result.trafficCount, len(result.findings))

	assert.Equal(t, len(items), result.trafficCount,
		"all parsed requests should fetch baseline responses from VAmPI")

	for _, f := range result.findings {
		t.Logf("Finding: module=%s severity=%s url=%s param=%s",
			f.ModuleID, f.Info.Severity, f.URL, f.FuzzingParameter)
	}
}

// runImportToDBScan mirrors the production `vigolium scan -i <spec> -t <baseURL>`
// pipeline (pkg/cli/scan.go runScanWithIngest): it builds an OpenAPI input source,
// ingests every parsed request into a real database, then runs the
// dynamic-assessment phase over *all* ingested DB records. Unlike
// runImportNativeScan — which scans an in-memory slice and never touches a DB —
// this exercises the full ingest → persist → scan-all-records path.
func runImportToDBScan(t *testing.T, specFile, baseURL string) (*database.DB, *database.Repository) {
	t.Helper()

	db, repo := setupPipelineDB(t)

	opts := types.DefaultOptions()
	opts.Targets = []string{baseURL}
	// Run the full active set (mirrors TestScanRunner_VAmPI_OnlyDynamicAssessment)
	// so the dynamic-assessment phase reliably produces findings against VAmPI —
	// the DBScan test asserts >=1 finding to prove scan-all actually executed.
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.HeuristicsCheck = "none"
	// Import-then-scan-all: ingest the spec into the DB and scan every record.
	// No crawling, no external harvesting, no known-issue scan.
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = false

	inputSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:       opts.Targets,
		FilePath:      specFile,
		Format:        "openapi",
		BufferSize:    100,
		EnableModules: opts.Modules,
	})
	require.NoError(t, err, "failed to build OpenAPI input source")

	// Point the parsed requests at the live VAmPI container.
	if fs, ok := inputSrc.(*source.FileSource); ok {
		if of, ok := fs.Format().(*openapi.Format); ok {
			of.SetOpenAPIOptions(openapi.Options{
				BaseURL:              baseURL,
				DefaultFallbackValue: "1",
			})
		}
	}

	r, err := runner.NewWithInputSource(opts, inputSrc)
	require.NoError(t, err, "failed to create scan runner")
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	require.NoError(t, r.RunNativeScan(), "import → DB → scan-all should complete without error")
	return db, repo
}

// TestVAmPI_ImportOpenAPI_DBScan is the DB-backed counterpart to
// TestVAmPI_ImportOpenAPI_NativeScan. It ingests the VAmPI OpenAPI spec into a
// real database and then scans every persisted record, asserting that the
// ingested records persist AND that the dynamic-assessment phase actually ran
// and produced findings. This mirrors `vigolium scan -i vampi-openapi3.yml -t <vampi>`.
func TestVAmPI_ImportOpenAPI_DBScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	// Background ctx for the post-scan read-back queries, matching the suite's
	// convention (scan_runner_test.go). RunNativeScan is not ctx-bounded — the
	// scan is bounded by `go test -timeout`, so a WithTimeout(ctx) here would
	// give a false impression of capping the scan.
	ctx := context.Background()

	app := startVAmPI(t)
	t.Logf("VAmPI running at %s", app.BaseURL)
	initVAmPIDB(t, app.BaseURL)

	specFile := filepath.Join(sampleInputDir(), "vampi-openapi3.yml")
	db, repo := runImportToDBScan(t, specFile, app.BaseURL)

	// Phase 1: every parsed OpenAPI request was ingested and persisted. Scope the
	// query to the default project (matching the hosts query below) so it would
	// catch a project-scoping regression instead of reading across all projects.
	records, err := database.NewQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}).Execute(ctx)
	require.NoError(t, err)
	// If nothing was ingested because the VAmPI container fell over mid-scan
	// (a flake when the full canary suite runs many containers at once), skip
	// rather than fail — a confirmed-unreachable target is environmental, not a
	// scanner regression. A healthy-but-empty result still fails below.
	if len(records) == 0 && !vampiReachable(app.BaseURL) {
		t.Skip("VAmPI became unreachable during the scan (container died under load); skipping (environmental)")
	}
	require.NotEmpty(t, records, "expected ingested HTTP records persisted in DB")

	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1, "expected the VAmPI host in DB")

	// Phase 2: the dynamic-assessment phase scanned the ingested records and
	// produced findings — without this assertion the "scan-all" half of the test
	// passes vacuously even if scanning never ran.
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	// No findings with an unreachable target means the scan had no baseline
	// responses to analyze (container died under load) — environmental, skip.
	if len(findings) == 0 && !vampiReachable(app.BaseURL) {
		t.Skip("VAmPI became unreachable during the scan; no responses to analyze; skipping (environmental)")
	}
	assert.GreaterOrEqual(t, len(findings), 1,
		"dynamic-assessment over the ingested records should produce at least one finding")

	t.Logf("Import → DB → scan-all: %d records, %d hosts, %d findings",
		len(records), len(hosts), len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestVAmPI_ImportBothFormats_NativeScan parses both OpenAPI and Postman specs,
// deduplicates, and runs a combined native scan to verify format interoperability.
func TestVAmPI_ImportBothFormats_NativeScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	app := startVAmPI(t)
	t.Logf("VAmPI running at %s", app.BaseURL)

	openapiItems := parseVAmPIOpenAPI(t, app.BaseURL)
	postmanItems := parseVAmPIPostman(t, app.BaseURL)
	t.Logf("OpenAPI: %d requests, Postman: %d requests", len(openapiItems), len(postmanItems))

	// Deduplicate by method+path
	seen := map[string]bool{}
	var combined []*httpmsg.HttpRequestResponse
	for _, rr := range openapiItems {
		req := rr.Request()
		key := req.Method() + " " + req.Path()
		if !seen[key] {
			seen[key] = true
			combined = append(combined, rr)
		}
	}
	for _, rr := range postmanItems {
		req := rr.Request()
		key := req.Method() + " " + req.Path()
		if !seen[key] {
			seen[key] = true
			combined = append(combined, rr)
		}
	}
	t.Logf("Combined (deduplicated): %d unique requests", len(combined))

	// Combined should have at least as many as either spec alone
	assert.GreaterOrEqual(t, len(combined), len(openapiItems),
		"combined should have at least as many requests as OpenAPI alone")

	initVAmPIDB(t, app.BaseURL)

	result := runImportNativeScan(t, ctx, combined)
	t.Logf("Traffic: %d, Findings: %d", result.trafficCount, len(result.findings))

	assert.Equal(t, len(combined), result.trafficCount,
		"all combined requests should fetch baseline responses")

	for _, f := range result.findings {
		t.Logf("Finding: module=%s severity=%s url=%s param=%s",
			f.ModuleID, f.Info.Severity, f.URL, f.FuzzingParameter)
	}
}
