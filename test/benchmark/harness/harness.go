package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestInfra holds the test infrastructure components shared across benchmark tests.
type TestInfra struct {
	HTTPClient  *httpRequester.Requester
	HostErrors  *hosterrors.Cache
	HostLimiter *hostlimit.HostRateLimiter
	Options     *types.Options
	ScanCtx     *modkit.ScanContext
}

// networkOnce ensures network.Init is called only once per test process.
// network.Init/Close manage global state (LevelDB) that cannot be safely
// re-initialized after Close, so we init once and never close during tests.
var networkOnce sync.Once
var networkInitErr error

// SetupTestInfra initializes HTTP client and services for benchmark tests.
// Network initialization is done once per process to avoid LevelDB close/reopen issues.
func SetupTestInfra() (*TestInfra, error) {
	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 2
	opts.MaxHostError = 10
	opts.MaxPerHost = 5

	networkOnce.Do(func() {
		networkInitErr = network.Init(opts)
	})
	if networkInitErr != nil {
		return nil, fmt.Errorf("failed to initialize network: %w", networkInitErr)
	}

	hostErrors := hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil)
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: opts.MaxPerHost,
	})

	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostLimiter,
		HostErrors:  hostErrors,
	}

	httpClient, err := httpRequester.NewRequester(opts, svc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}

	scanCtx := &modkit.ScanContext{
		DedupManager: nil,
	}

	return &TestInfra{
		HTTPClient:  httpClient,
		HostErrors:  hostErrors,
		HostLimiter: hostLimiter,
		Options:     opts,
		ScanCtx:     scanCtx,
	}, nil
}

// Cleanup performs cleanup after tests.
// Note: network.Close() is intentionally NOT called here because it destroys
// global LevelDB state that cannot be re-initialized. The process exit handles cleanup.
func (infra *TestInfra) Cleanup() {
	if infra.HostErrors != nil {
		infra.HostErrors.Close()
	}
	if infra.HostLimiter != nil {
		_ = infra.HostLimiter.Close()
	}
}

// LoadDefinition loads a BenchmarkDefinition from a YAML file.
func LoadDefinition(path string) (*BenchmarkDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read definition file %s: %w", path, err)
	}

	var def BenchmarkDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse definition file %s: %w", path, err)
	}

	// Expand environment variables in build_context (e.g. $XBOW_SOURCE_DIR)
	if def.App.BuildContext != "" {
		def.App.BuildContext = os.ExpandEnv(def.App.BuildContext)
	}

	// Apply defaults
	for i := range def.TestCases {
		if def.TestCases[i].Method == "" {
			def.TestCases[i].Method = "GET"
		}
		if def.TestCases[i].Assertion == "" {
			def.TestCases[i].Assertion = "strict"
		}
		if def.TestCases[i].ScanMode == "" {
			def.TestCases[i].ScanMode = "active"
		}
		if def.TestCases[i].MinFindings == 0 {
			def.TestCases[i].MinFindings = 1
		}
	}

	return &def, nil
}

// LoadDefinitionsFromDir loads all YAML definitions from a directory.
func LoadDefinitionsFromDir(dir string) ([]*BenchmarkDefinition, error) {
	var defs []*BenchmarkDefinition

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob definitions: %w", err)
	}

	for _, f := range files {
		def, err := LoadDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}

	return defs, nil
}

// ResolveActiveModules returns active modules matching the given IDs.
// Returns an error if any module ID is not found.
func ResolveActiveModules(ids []string) ([]modules.ActiveModule, error) {
	mods := modules.GetActiveModulesByIDs(ids)
	if len(mods) != len(ids) {
		found := make(map[string]bool)
		for _, m := range mods {
			found[m.ID()] = true
		}
		var missing []string
		for _, id := range ids {
			if !found[id] {
				missing = append(missing, id)
			}
		}
		return mods, fmt.Errorf("active modules not found: %v", missing)
	}
	return mods, nil
}

// ResolvePassiveModules returns passive modules matching the given IDs.
// Returns an error if any module ID is not found.
func ResolvePassiveModules(ids []string) ([]modules.PassiveModule, error) {
	mods := modules.GetPassiveModulesByIDs(ids)
	if len(mods) != len(ids) {
		found := make(map[string]bool)
		for _, m := range mods {
			found[m.ID()] = true
		}
		var missing []string
		for _, id := range ids {
			if !found[id] {
				missing = append(missing, id)
			}
		}
		return mods, fmt.Errorf("passive modules not found: %v", missing)
	}
	return mods, nil
}

// RunActiveTestCase executes a single active test case against a base URL.
// It dispatches to the correct scan method based on the module's ScanScopes:
//   - ScanScopeInsertionPoint: creates insertion points, calls ScanPerInsertionPoint for each
//   - ScanScopeRequest: calls ScanPerRequest once
//   - ScanScopeHost: calls ScanPerHost once
func RunActiveTestCase(t *testing.T, tc TestCase, baseURL string, infra *TestInfra) []TestResult {
	t.Helper()
	var results []TestResult

	fullURL := baseURL + tc.Endpoint

	var rr *httpmsg.HttpRequestResponse
	var err error
	switch {
	case tc.Body != "":
		rr, err = buildRequestWithMethodAndBody(fullURL, tc.Method, tc.Body, tc.Headers)
	case tc.Method != "" && tc.Method != "GET":
		rr, err = buildRequestWithMethod(fullURL, tc.Method, tc.Headers)
	default:
		rr, err = buildRequestWithHeaders(fullURL, tc.Headers)
	}
	require.NoError(t, err, "Failed to create request from URL: %s", fullURL)

	activeMods, err := ResolveActiveModules(tc.Modules)
	if err != nil {
		t.Logf("Warning: %v", err)
	}

	for _, mod := range activeMods {
		start := time.Now()
		var findings []*output.ResultEvent
		var scanErr error

		scanScopes := mod.ScanScopes()

		switch {
		case scanScopes.Has(modkit.ScanScopeInsertionPoint):
			findings, scanErr = runPerInsertionPoint(t, tc, rr, mod, infra)

		case scanScopes.Has(modkit.ScanScopeRequest):
			findings, scanErr = mod.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)

		case scanScopes.Has(modkit.ScanScopeHost):
			findings, scanErr = mod.ScanPerHost(rr, infra.HTTPClient, infra.ScanCtx)

		default:
			t.Logf("[%s] %s: unknown ScanScope %v, skipping", tc.ID, mod.ID(), scanScopes)
		}

		duration := time.Since(start)

		tr := TestResult{
			TestCase:     tc,
			ModuleID:     mod.ID(),
			FindingCount: len(findings),
			Duration:     duration,
			Error:        scanErr,
		}

		if scanErr != nil {
			t.Logf("[%s] %s error: %v", tc.ID, mod.ID(), scanErr)
			tr.Passed = false
		} else {
			ApplyAssertion(t, tc, mod.ID(), findings)
			tr.Passed = evaluateAssertion(tc, len(findings))
		}

		for _, f := range findings {
			t.Logf("[%s] Finding: module=%s param=%s url=%s",
				tc.ID, f.ModuleID, f.FuzzingParameter, f.URL)
		}

		results = append(results, tr)
	}

	return results
}

// runPerInsertionPoint creates insertion points from the request and calls
// ScanPerInsertionPoint for each one, collecting all findings.
func runPerInsertionPoint(t *testing.T, tc TestCase, rr *httpmsg.HttpRequestResponse, mod modules.ActiveModule, infra *TestInfra) ([]*output.ResultEvent, error) {
	t.Helper()

	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		return nil, fmt.Errorf("failed to create insertion points: %w", err)
	}

	// Filter insertion points by the module's allowed types
	allowedTypes := mod.AllowedInsertionPointTypes()
	var filteredPoints []httpmsg.InsertionPoint
	for _, ip := range points {
		if allowedTypes.Contains(ip.Type()) {
			filteredPoints = append(filteredPoints, ip)
		}
	}

	if len(filteredPoints) == 0 {
		t.Logf("[%s] %s: no insertion points found (total=%d, filtered=0)",
			tc.ID, mod.ID(), len(points))
		return nil, nil
	}

	t.Logf("[%s] %s: scanning %d insertion points", tc.ID, mod.ID(), len(filteredPoints))

	var allFindings []*output.ResultEvent
	for _, ip := range filteredPoints {
		findings, err := mod.ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		if err != nil {
			t.Logf("[%s] %s: insertion point %q error: %v", tc.ID, mod.ID(), ip.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// RunPassiveTestCase executes a single passive test case against a base URL.
func RunPassiveTestCase(t *testing.T, tc TestCase, baseURL string, infra *TestInfra) []TestResult {
	t.Helper()
	var results []TestResult

	fullURL := baseURL + tc.Endpoint
	rr, err := FetchForPassiveScan(fullURL, tc.Headers, infra)
	require.NoError(t, err, "Failed to fetch URL for passive scan: %s", fullURL)

	passiveMods, err := ResolvePassiveModules(tc.Modules)
	if err != nil {
		t.Logf("Warning: %v", err)
	}

	for _, mod := range passiveMods {
		start := time.Now()
		var findings []*output.ResultEvent
		var scanErr error

		scanScopes := mod.ScanScopes()
		if scanScopes.Has(modkit.ScanScopeRequest) {
			findings, scanErr = mod.ScanPerRequest(rr, infra.ScanCtx)
		} else if scanScopes.Has(modkit.ScanScopeHost) {
			findings, scanErr = mod.ScanPerHost(rr, infra.ScanCtx)
		}

		duration := time.Since(start)

		tr := TestResult{
			TestCase:     tc,
			ModuleID:     mod.ID(),
			FindingCount: len(findings),
			Duration:     duration,
			Error:        scanErr,
		}

		if scanErr != nil {
			t.Logf("[%s] %s error: %v", tc.ID, mod.ID(), scanErr)
			tr.Passed = false
		} else {
			ApplyAssertion(t, tc, mod.ID(), findings)
			tr.Passed = evaluateAssertion(tc, len(findings))
		}

		for _, f := range findings {
			t.Logf("[%s] Finding: module=%s matched=%s",
				tc.ID, f.ModuleID, f.Matched)
		}

		results = append(results, tr)
	}

	return results
}

// ApplyAssertion checks findings against the test case assertion mode.
func ApplyAssertion(t *testing.T, tc TestCase, moduleID string, findings []*output.ResultEvent) {
	t.Helper()

	switch tc.Assertion {
	case "strict":
		assert.GreaterOrEqual(t, len(findings), tc.MinFindings,
			"[%s] Expected >= %d findings from %s at %s",
			tc.ID, tc.MinFindings, moduleID, tc.Endpoint)
	case "soft":
		if len(findings) < tc.MinFindings {
			t.Logf("[%s] Soft assertion: expected >= %d findings from %s at %s, got %d",
				tc.ID, tc.MinFindings, moduleID, tc.Endpoint, len(findings))
		}
	case "negative":
		assert.Equal(t, 0, len(findings),
			"[%s] Expected 0 findings from %s at %s (negative test)",
			tc.ID, moduleID, tc.Endpoint)
	default:
		t.Logf("[%s] Unknown assertion type: %s, treating as soft", tc.ID, tc.Assertion)
	}
}

// evaluateAssertion returns whether the finding count satisfies the assertion.
func evaluateAssertion(tc TestCase, findingCount int) bool {
	switch tc.Assertion {
	case "strict":
		return findingCount >= tc.MinFindings
	case "soft":
		return true // soft assertions never fail
	case "negative":
		return findingCount == 0
	default:
		return true
	}
}

// SetupAppAuth performs app-specific authentication/setup and returns headers
// (e.g., Cookie headers) to inject into all test case requests.
// Returns nil headers if the app requires no special setup.
func SetupAppAuth(t *testing.T, appName, baseURL string) (map[string]string, error) {
	t.Helper()

	switch appName {
	case "dvwa":
		cookieStr, err := SetupDVWA(t, baseURL)
		if err != nil {
			return nil, err
		}
		return map[string]string{"Cookie": cookieStr}, nil
	case "vampi":
		return setupVAmPI(t, baseURL)
	case "oopssec-store":
		return setupOopssecStore(t, baseURL)
	default:
		return nil, nil
	}
}

// setupVAmPI initializes the VAmPI database, registers a test user, and
// returns an Authorization header with a JWT token for authenticated endpoints.
func setupVAmPI(t *testing.T, baseURL string) (map[string]string, error) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}

	// Step 1: Initialize database
	resp, err := client.Get(baseURL + "/createdb")
	if err != nil {
		return nil, fmt.Errorf("failed to init VAmPI database: %w", err)
	}
	_ = resp.Body.Close()
	t.Logf("VAmPI setup: database initialized (status=%d)", resp.StatusCode)

	// Step 2: Register a test user
	regBody := `{"username":"benchuser","password":"Bench!pass123","email":"bench@test.com"}`
	regResp, err := client.Post(baseURL+"/users/v1/register",
		"application/json", bytes.NewBufferString(regBody))
	if err != nil {
		return nil, fmt.Errorf("failed to register VAmPI user: %w", err)
	}
	_ = regResp.Body.Close()
	t.Logf("VAmPI setup: user registered (status=%d)", regResp.StatusCode)

	// Step 3: Login to get JWT token
	loginBody := `{"username":"benchuser","password":"Bench!pass123"}`
	loginResp, err := client.Post(baseURL+"/users/v1/login",
		"application/json", bytes.NewBufferString(loginBody))
	if err != nil {
		return nil, fmt.Errorf("failed to login VAmPI user: %w", err)
	}
	defer func() { _ = loginResp.Body.Close() }()

	body, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read VAmPI login response: %w", err)
	}

	var loginResult struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(body, &loginResult); err != nil || loginResult.AuthToken == "" {
		t.Logf("VAmPI setup: login response: %s", string(body))
		return nil, fmt.Errorf("failed to extract JWT token from VAmPI login")
	}

	t.Logf("VAmPI setup: JWT token obtained (%d chars)", len(loginResult.AuthToken))
	return map[string]string{
		"Authorization": "Bearer " + loginResult.AuthToken,
	}, nil
}

// setupOopssecStore registers a test user, logs in, and returns an
// Authorization header with a JWT token for authenticated endpoints.
func setupOopssecStore(t *testing.T, baseURL string) (map[string]string, error) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}

	// Step 1: Register a test user
	regBody := `{"email":"bench@test.com","password":"benchmark123","name":"Benchmark"}`
	regResp, err := client.Post(baseURL+"/api/auth/signup",
		"application/json", bytes.NewBufferString(regBody))
	if err != nil {
		return nil, fmt.Errorf("failed to register oopssec-store user: %w", err)
	}
	_ = regResp.Body.Close()
	t.Logf("oopssec-store setup: user registered (status=%d)", regResp.StatusCode)

	// Step 2: Login to get JWT token
	loginBody := `{"email":"bench@test.com","password":"benchmark123"}`
	loginResp, err := client.Post(baseURL+"/api/auth/login",
		"application/json", bytes.NewBufferString(loginBody))
	if err != nil {
		return nil, fmt.Errorf("failed to login oopssec-store user: %w", err)
	}
	defer func() { _ = loginResp.Body.Close() }()

	body, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read oopssec-store login response: %w", err)
	}

	var loginResult struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &loginResult); err != nil || loginResult.Token == "" {
		t.Logf("oopssec-store setup: login response: %s", string(body))
		return nil, fmt.Errorf("failed to extract JWT token from oopssec-store login")
	}

	t.Logf("oopssec-store setup: JWT token obtained (%d chars)", len(loginResult.Token))
	return map[string]string{
		"Authorization": "Bearer " + loginResult.Token,
	}, nil
}

// MergeHeaders merges auth headers into test case headers.
// Test case headers take precedence over auth headers, except for Cookie
// which is merged additively (appended with "; ") so auth cookies aren't lost.
func MergeHeaders(authHeaders, tcHeaders map[string]string) map[string]string {
	if len(authHeaders) == 0 {
		return tcHeaders
	}
	merged := make(map[string]string, len(authHeaders)+len(tcHeaders))
	maps.Copy(merged, authHeaders)

	for k, v := range tcHeaders {
		if strings.EqualFold(k, "Cookie") {
			if existing, ok := merged["Cookie"]; ok {
				merged["Cookie"] = existing + "; " + v
				continue
			}
		}
		merged[k] = v
	}
	return merged
}

// buildRequestWithHeaders creates an HttpRequestResponse from a URL with optional extra headers.
// If headers is nil or empty, it behaves identically to httpmsg.GetRawRequestFromURL.
func buildRequestWithHeaders(rawURL string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	if len(headers) == 0 {
		return httpmsg.GetRawRequestFromURL(rawURL)
	}

	// First create the base request
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		return nil, err
	}

	// Inject extra headers into the raw request by rebuilding it
	rawReq := string(rr.Request().Raw())
	// Insert headers before the final \r\n\r\n
	before, _, found := strings.Cut(rawReq, "\r\n\r\n")
	if !found {
		return rr, nil
	}

	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}

	newRaw := before + "\r\n" + sb.String() + "\r\n"
	newRR, err := httpmsg.ParseRawRequest(newRaw)
	if err != nil {
		return rr, nil // Fall back to original if parsing fails
	}

	// Preserve the service from the original
	return newRR.WithService(rr.Service()), nil
}

// buildRequestWithMethodAndBody creates an HttpRequestResponse with the given method, body, and optional headers.
func buildRequestWithMethodAndBody(rawURL, method, body string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	parsed, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		return nil, err
	}

	// Rebuild the raw request with the specified method and body
	rawReq := string(parsed.Request().Raw())
	// Replace "GET" with the target method in the request line
	rawReq = strings.Replace(rawReq, "GET ", method+" ", 1)

	// Split at the end of headers
	before, _, found := strings.Cut(rawReq, "\r\n\r\n")
	if !found {
		return nil, fmt.Errorf("malformed raw request: no header terminator")
	}

	var sb strings.Builder
	sb.WriteString(before)
	sb.WriteString("\r\n")

	// Add Content-Length
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))

	// Add custom headers
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}

	sb.WriteString("\r\n")
	sb.WriteString(body)

	newRR, err := httpmsg.ParseRawRequest(sb.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s request: %w", method, err)
	}

	return newRR.WithService(parsed.Service()), nil
}

// buildRequestWithMethod creates an HttpRequestResponse with the given method (no body) and optional headers.
// Useful for HEAD, OPTIONS, DELETE-without-body, etc.
func buildRequestWithMethod(rawURL, method string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	rr, err := buildRequestWithHeaders(rawURL, headers)
	if err != nil {
		return nil, err
	}

	// Replace "GET" with the target method in the request line
	rawReq := string(rr.Request().Raw())
	rawReq = strings.Replace(rawReq, "GET ", method+" ", 1)

	newRR, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return rr, nil // Fall back to original if parsing fails
	}

	return newRR.WithService(rr.Service()), nil
}

// DefinitionsDir returns the absolute path to the definitions directory,
// assuming it is located relative to the test file at ../definitions/.
func DefinitionsDir() string {
	// Walk up from any test directory to find test/benchmark/definitions
	candidates := []string{
		"../definitions",
		"../../definitions",
		"test/benchmark/definitions",
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	// Fallback: try relative to working directory
	return "test/benchmark/definitions"
}
