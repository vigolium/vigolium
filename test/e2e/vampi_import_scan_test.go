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

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
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
