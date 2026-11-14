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
	"sync/atomic"
	"testing"
	"time"

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
	"github.com/vigolium/vigolium/pkg/modules/modtest"
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
	opts.Timeout = 30 * time.Second
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
// Scope dispatch (per host / per request / per insertion point) is
// modtest.RunActive, shared with the benign sweep in pkg/modules.
func RunActiveTestCase(t testing.TB, tc TestCase, baseURL string, infra *TestInfra) []TestResult {
	t.Helper()
	var results []TestResult

	// An unresolvable module ID used to log a warning and run the remaining
	// modules - with every ID stale the case ran nothing and passed. Resolve
	// before sending anything so a stale definition fails fast.
	activeMods, err := ResolveActiveModules(tc.Modules)
	if err != nil {
		t.Fatalf("[%s] %v", tc.ID, err)
	}

	fullURL := baseURL + tc.Endpoint

	var rr *httpmsg.HttpRequestResponse
	switch {
	case tc.Body != "":
		rr, err = buildRequestWithMethodAndBody(fullURL, tc.Method, tc.Body, tc.Headers)
	case tc.Method != "" && tc.Method != "GET":
		rr, err = buildRequestWithMethod(fullURL, tc.Method, tc.Headers)
	default:
		rr, err = buildRequestWithHeaders(fullURL, tc.Headers)
	}
	require.NoError(t, err, "Failed to create request from URL: %s", fullURL)

	// Modules receive records that already carry a response in a real scan (ingested
	// traffic, discovery hits). The synthetic record built above has none, so send it
	// once and scan the answered record - modules that compare against a baseline
	// response would otherwise see nothing to compare with.
	if baseline := fetchBaseline(t, rr, infra); baseline != nil {
		rr = baseline
	}

	for _, mod := range activeMods {
		start := time.Now()
		// Per-module send counter: the request count lands in the report.
		var sent atomic.Int64
		findings, scanErr := modtest.RunActive(mod, rr, infra.HTTPClient.WithSendCounter(&sent), infra.ScanCtx)
		duration := time.Since(start)

		tr := TestResult{
			TestCase:     tc,
			ModuleID:     mod.ID(),
			FindingCount: len(findings),
			Duration:     duration,
			Requests:     sent.Load(),
			Error:        scanErr,
		}

		if scanErr != nil {
			t.Logf("[%s] %s error: %v", tc.ID, mod.ID(), scanErr)
		}
		tr.Passed = ApplyAssertion(t, tc, mod.ID(), findings, scanErr)

		for _, f := range findings {
			t.Logf("[%s] Finding: module=%s param=%s url=%s",
				tc.ID, f.ModuleID, f.FuzzingParameter, f.URL)
		}

		results = append(results, tr)
	}

	return results
}

// fetchBaseline sends rr once and returns rr paired with the response, or nil
// when rr already has one or the send fails (the caller then scans the
// response-less record, as before).
func fetchBaseline(t testing.TB, rr *httpmsg.HttpRequestResponse, infra *TestInfra) *httpmsg.HttpRequestResponse {
	t.Helper()

	if rr == nil || rr.HasResponse() {
		return nil
	}

	chain, _, err := infra.HTTPClient.Execute(rr, httpRequester.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		t.Logf("baseline request failed, scanning without a response: %v", err)
		return nil
	}
	defer chain.Close()

	// FullResponseString copies out of the chain's pooled buffer, which Close
	// reclaims - so the copy has to happen before this function returns.
	raw := chain.FullResponseString()
	if raw == "" {
		return nil
	}
	return rr.WithResponse(httpmsg.NewHttpResponse([]byte(raw)))
}

// RunPassiveTestCase executes a single passive test case against a base URL.
func RunPassiveTestCase(t testing.TB, tc TestCase, baseURL string, infra *TestInfra) []TestResult {
	t.Helper()
	var results []TestResult

	passiveMods, err := ResolvePassiveModules(tc.Modules)
	if err != nil {
		t.Fatalf("[%s] %v", tc.ID, err)
	}

	fullURL := baseURL + tc.Endpoint
	rr, err := FetchForPassiveScan(fullURL, tc.Headers, infra)
	require.NoError(t, err, "Failed to fetch URL for passive scan: %s", fullURL)

	for _, mod := range passiveMods {
		start := time.Now()
		var findings []*output.ResultEvent
		var scanErr error

		scanScopes := mod.ScanScopes()
		switch {
		case scanScopes.Has(modkit.ScanScopeRequest):
			findings, scanErr = mod.ScanPerRequest(rr, infra.ScanCtx)
		case scanScopes.Has(modkit.ScanScopeHost):
			findings, scanErr = mod.ScanPerHost(rr, infra.ScanCtx)
		default:
			scanErr = fmt.Errorf("unknown ScanScope %v", scanScopes)
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
		}
		tr.Passed = ApplyAssertion(t, tc, mod.ID(), findings, scanErr)

		for _, f := range findings {
			t.Logf("[%s] Finding: module=%s matched=%s",
				tc.ID, f.ModuleID, f.Matched)
		}

		results = append(results, tr)
	}

	return results
}

// ApplyAssertion checks one module's outcome against the test case assertion
// mode, failing t when it does not hold, and reports whether it held.
func ApplyAssertion(t testing.TB, tc TestCase, moduleID string, findings []*output.ResultEvent, scanErr error) bool {
	t.Helper()

	if tc.Assertion == "soft" && len(findings) < tc.MinFindings {
		t.Logf("[%s] Soft assertion (%s): expected >= %d findings from %s at %s, got %d",
			tc.ID, tc.SoftReason, tc.MinFindings, moduleID, tc.Endpoint, len(findings))
	}
	if msg := AssertionFailure(tc, len(findings), scanErr); msg != "" {
		t.Errorf("[%s] %s at %s: %s", tc.ID, moduleID, tc.Endpoint, msg)
		return false
	}
	return true
}

// AssertionFailure returns why a module outcome fails the case's assertion, or
// "" when it holds. Kept free of *testing.T so the rules are unit-testable.
//
//   - strict: >= MinFindings (exactly ExpectedFindings when set); a module error fails.
//   - negative: zero findings; a module error fails (an erroring module proves nothing).
//   - soft: never fails, so it must carry a SoftReason (definitions lint).
//   - anything else fails: an unknown assertion used to pass as soft.
func AssertionFailure(tc TestCase, findingCount int, scanErr error) string {
	switch tc.Assertion {
	case "strict":
		if scanErr != nil {
			return fmt.Sprintf("module error: %v", scanErr)
		}
		if tc.ExpectedFindings != nil {
			if findingCount != *tc.ExpectedFindings {
				return fmt.Sprintf("expected exactly %d findings, got %d", *tc.ExpectedFindings, findingCount)
			}
			return ""
		}
		if findingCount < tc.MinFindings {
			return fmt.Sprintf("expected >= %d findings, got %d", tc.MinFindings, findingCount)
		}
		return ""
	case "negative":
		if scanErr != nil {
			return fmt.Sprintf("module error: %v", scanErr)
		}
		if findingCount != 0 {
			return fmt.Sprintf("expected 0 findings (negative case), got %d", findingCount)
		}
		return ""
	case "soft":
		return ""
	default:
		return fmt.Sprintf("unknown assertion %q (want strict, negative or soft)", tc.Assertion)
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

// RepoRoot returns the absolute path to the repository root, found by walking up
// from the working directory until a go.mod is seen. Returns "" if none is found.
//
// Benchmark definitions spell paths (build_context and friends) relative to the
// repo root, but `go test` runs each package with its own directory as the working
// directory - so those paths have to be re-anchored before they hit the filesystem.
func RepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// ResolveRepoPath re-anchors a repo-root-relative path against the repo root.
// Absolute paths, and paths that already resolve from the working directory, are
// returned unchanged.
func ResolveRepoPath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	root := RepoRoot()
	if root == "" {
		return path
	}
	return filepath.Join(root, path)
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
