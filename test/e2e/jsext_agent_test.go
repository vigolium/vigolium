//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/llm"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// agentExtensionsDir returns the path to the agent-extensions testdata directory.
func agentExtensionsDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", "agent-extensions")
}

// ── Mock LLM client ──────────────────────────────────────────────────────────

// mockAgentClient is a keyword-driven LLM mock.
// It inspects message content and returns the first matching response string.
type mockAgentClient struct {
	rules    []mockRule // evaluated in order
	fallback string
}

type mockRule struct {
	keyword  string // substring to match in any message content
	response string // response to return when matched
}

func (m *mockAgentClient) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	for _, msg := range req.Messages {
		for _, rule := range m.rules {
			if strings.Contains(msg.Content, rule.keyword) {
				return &llm.CompletionResponse{Content: rule.response, Model: "mock", TokensIn: 10, TokensOut: 20}, nil
			}
		}
	}
	return &llm.CompletionResponse{Content: m.fallback, Model: "mock"}, nil
}

// newXSSMockClient returns a mock LLM client pre-configured for XSS scanner tests.
// generatePayloads → payloads JSON, analyzeResponse → vulnerable=true.
func newXSSMockClient() *mockAgentClient {
	return &mockAgentClient{
		rules: []mockRule{
			{
				keyword: "Generate",
				response: `{"payloads":["<script>alert('VGNM')</script>","<img src=x onerror=alert('VGNM')>","javascript:alert('VGNM')"]}`,
			},
			{
				keyword: "Analyze",
				response: `{"vulnerable":true,"confidence":"high","evidence":"XSS payload reflected verbatim in response","details":"Payload found unencoded in HTML body"}`,
			},
		},
		fallback: `{"payloads":[]}`,
	}
}

// newFPFilterMockClient returns a mock configured for FP filter tests.
// Messages containing "SQL" → confirmed=false (drop), others → confirmed=true.
func newFPFilterMockClient() *mockAgentClient {
	return &mockAgentClient{
		rules: []mockRule{
			{
				keyword:  "SQL Injection false alarm",
				response: `{"confirmed":false,"confidence":"high","reasoning":"Response body shows no actual SQL error, pattern match was a false positive","false_positive_indicators":["response has 200 status","no SQL error keywords in body"]}`,
			},
			{
				keyword:  "Reflected XSS",
				response: `{"confirmed":true,"confidence":"high","reasoning":"Payload reflected verbatim in response without encoding","false_positive_indicators":[]}`,
			},
		},
		fallback: `{"confirmed":true,"confidence":"medium","reasoning":"Unable to determine definitively","false_positive_indicators":[]}`,
	}
}

// newResponseAnalyzerMockClient returns a mock for the response analyzer YAML extension.
// Responses containing "SQLSTATE" get an ISSUE answer; clean responses get OK.
func newResponseAnalyzerMockClient() *mockAgentClient {
	return &mockAgentClient{
		rules: []mockRule{
			{
				keyword:  "SQLSTATE",
				response: "ISSUE:SQL Error Disclosure:Response contains a raw SQL error (SQLSTATE) that reveals database internals",
			},
			{
				keyword:  "stack trace",
				response: "ISSUE:Stack Trace Leak:Response contains a server stack trace revealing internal file paths",
			},
		},
		fallback: "OK",
	}
}

// engineWithAgentClient is a helper that creates a JS engine with the given LLM mock.
func engineWithAgentClient(t *testing.T, cfg *config.ExtensionsConfig, infra *TestInfra, client llm.Client) *jsext.Engine {
	t.Helper()
	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, &jsext.EngineOptions{
		LLMClient: client,
	})
	require.NoError(t, err)
	return engine
}

// ── Test: AI XSS Scanner ─────────────────────────────────────────────────────

// TestAgentExt_XSSScanner_FindsReflection verifies that ai_xss_scanner.js:
//   - loads as an active module
//   - generates payloads via the mock LLM
//   - sends them to a local httptest server that reflects all query params
//   - confirms the reflection via the mock LLM
//   - emits a high-severity finding
func TestAgentExt_XSSScanner_FindsReflection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Local echo server: reflects the "q" query param verbatim in the body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		val := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", val)
	}))
	defer srv.Close()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_xss_scanner.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newXSSMockClient())

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "active-ext-ai-xss-scanner", activeMods[0].ID())
	assert.Equal(t, "AI-Augmented XSS Scanner", activeMods[0].Name())

	// Build a request targeting our echo server
	host := strings.TrimPrefix(srv.URL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	rawReq := fmt.Sprintf("GET /search?q=test HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
	require.NoError(t, err)
	require.NotEmpty(t, ips)

	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	var findings []*output.ResultEvent
	for _, ip := range ips {
		results, scanErr := activeMods[0].ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, scanErr)
		findings = append(findings, results...)
	}

	require.NotEmpty(t, findings, "AI XSS scanner should produce findings against an echo endpoint")
	for _, f := range findings {
		t.Logf("Finding: %s (severity=%s, matched=%s)", f.Info.Name, f.Info.Severity, f.Matched)
		assert.Contains(t, f.Info.Name, "AI-Confirmed XSS")
		assert.Contains(t, f.Info.Name, "q") // insertion point parameter name
		assert.NotEmpty(t, f.Request, "Finding should include request evidence")
		assert.NotEmpty(t, f.Response, "Finding should include response evidence")
	}
}

// TestAgentExt_XSSScanner_NoFindingOnCleanEndpoint verifies that the scanner
// does not produce findings when the response does not reflect any XSS pattern.
func TestAgentExt_XSSScanner_NoFindingOnCleanEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Server that always returns a static, clean response
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_xss_scanner.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newXSSMockClient())

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	host := strings.TrimPrefix(srv.URL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	rawReq := fmt.Sprintf("GET /api?id=1 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
	require.NoError(t, err)

	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	var findings []*output.ResultEvent
	for _, ip := range ips {
		results, scanErr := activeMods[0].ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, scanErr)
		findings = append(findings, results...)
	}

	assert.Empty(t, findings, "AI XSS scanner should not produce findings when payload is not reflected")
	t.Log("No false positives on clean endpoint — OK")
}

// TestAgentExt_XSSScanner_GracefulFallbackWithoutLLM verifies that the module
// loads and produces no findings (graceful no-op) when LLMClient is nil.
func TestAgentExt_XSSScanner_GracefulFallbackWithoutLLM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_xss_scanner.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	// Nil LLMClient — agent API should not be set up
	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, &jsext.EngineOptions{LLMClient: nil})
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1, "Module should still load even without LLM client")

	rawReq := "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
	require.NoError(t, err)

	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	var findings []*output.ResultEvent
	for _, ip := range ips {
		results, scanErr := activeMods[0].ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, scanErr)
		findings = append(findings, results...)
	}

	assert.Empty(t, findings, "Module should silently no-op when LLM client is not configured")
	t.Log("Graceful fallback without LLM client — OK")
}

// ── Test: AI False Positive Filter ───────────────────────────────────────────

// TestAgentExt_FPFilter_DropsHighConfidenceFalsePositive verifies that the
// post-hook drops a finding when the LLM says it is a false positive with
// high confidence.
func TestAgentExt_FPFilter_DropsHighConfidenceFalsePositive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_false_positive_filter.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newFPFilterMockClient())

	postHooks := engine.PostHooks()
	require.Len(t, postHooks, 1)
	hookChain := jsext.NewHookChain(nil, postHooks)

	// A "SQL Injection false alarm" finding — the mock client will say confirmed=false
	fpResult := &output.ResultEvent{
		URL:      "https://example.com/api",
		Matched:  "SQLSTATE",
		Request:  "GET /api?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}",
		Info: output.Info{
			Name:        "SQL Injection false alarm",
			Description: "Possible SQL injection detected by pattern",
			Severity:    severity.High,
		},
	}

	dropped, err := hookChain.RunPostHooks(fpResult)
	require.NoError(t, err)
	assert.Nil(t, dropped, "High-confidence false positive should be dropped by post-hook")
	t.Log("High-confidence FP correctly dropped — OK")
}

// TestAgentExt_FPFilter_AnnotatesConfirmedFinding verifies that confirmed
// findings are tagged with [AI-verified] and pass through.
func TestAgentExt_FPFilter_AnnotatesConfirmedFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_false_positive_filter.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newFPFilterMockClient())
	hookChain := jsext.NewHookChain(nil, engine.PostHooks())

	// A "Reflected XSS" finding — the mock client will say confirmed=true
	xssResult := &output.ResultEvent{
		URL:      "https://example.com/search",
		Matched:  "<script>alert(1)</script>",
		Request:  "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\n<html><body><script>alert(1)</script></body></html>",
		Info: output.Info{
			Name:        "Reflected XSS",
			Description: "Payload reflected in response",
			Severity:    severity.High,
		},
	}

	verified, err := hookChain.RunPostHooks(xssResult)
	require.NoError(t, err)
	require.NotNil(t, verified, "Confirmed finding should not be dropped")
	assert.Contains(t, verified.Info.Name, "[AI-verified]", "Name should be prefixed with AI-verified")
	assert.Contains(t, verified.Info.Description, "AI reasoning:", "Description should include LLM reasoning")
	assert.Equal(t, severity.High, verified.Info.Severity, "Severity should be preserved")
	t.Logf("Verified finding: %s", verified.Info.Name)
}

// TestAgentExt_FPFilter_PassesThroughWithoutRequestResponse verifies that
// findings without request/response data are passed through unchanged.
func TestAgentExt_FPFilter_PassesThroughWithoutRequestResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_false_positive_filter.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newFPFilterMockClient())
	hookChain := jsext.NewHookChain(nil, engine.PostHooks())

	// Finding without request+response data
	noEvidenceResult := &output.ResultEvent{
		URL:     "https://example.com",
		Matched: "something",
		Info:    output.Info{Name: "Generic Finding", Severity: severity.Medium},
	}

	passThrough, err := hookChain.RunPostHooks(noEvidenceResult)
	require.NoError(t, err)
	require.NotNil(t, passThrough, "Finding without evidence should pass through")
	assert.Equal(t, "Generic Finding", passThrough.Info.Name, "Name should be unchanged")
	t.Log("Pass-through for evidence-less finding — OK")
}

// TestAgentExt_FPFilter_GracefulFallbackWithoutLLM verifies that the post-hook
// passes all findings through unchanged when LLMClient is nil.
func TestAgentExt_FPFilter_GracefulFallbackWithoutLLM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_false_positive_filter.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, &jsext.EngineOptions{LLMClient: nil})
	require.NoError(t, err)

	hookChain := jsext.NewHookChain(nil, engine.PostHooks())

	result := &output.ResultEvent{
		URL:      "https://example.com/api",
		Request:  "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\nOK",
		Info:     output.Info{Name: "Some Finding", Severity: severity.High},
	}

	passThrough, err := hookChain.RunPostHooks(result)
	require.NoError(t, err)
	require.NotNil(t, passThrough, "Finding should pass through unchanged without LLM client")
	assert.Equal(t, "Some Finding", passThrough.Info.Name, "Name must not be modified without LLM")
	t.Log("Graceful fallback without LLM client — OK")
}

// ── Test: AI Response Analyzer (YAML extension with script) ─────────────────

// TestAgentExt_ResponseAnalyzerYAML_DetectsIssue verifies that the YAML
// extension with inline script calls ask() and emits a finding when the LLM
// returns an ISSUE: response.
func TestAgentExt_ResponseAnalyzerYAML_DetectsIssue(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_response_analyzer.vgm.yaml")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newResponseAnalyzerMockClient())

	passiveMods := engine.PassiveModules()
	require.Len(t, passiveMods, 1, "YAML extension with script should load as a passive module")
	assert.Equal(t, "passive-ext-ai-response-analyzer", passiveMods[0].ID())
	assert.Equal(t, "AI Response Analyzer", passiveMods[0].Name())

	t.Run("DetectsSQLError", func(t *testing.T) {
		rawReq := "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n" +
			"SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, scanErr := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, scanErr)
		require.NotEmpty(t, results, "SQL error in response should produce a finding")

		assert.Contains(t, results[0].Info.Name, "AI-detected")
		assert.Contains(t, results[0].Info.Name, "SQL")
		assert.Contains(t, results[0].Matched, "SQL")
		t.Logf("Finding: %s — %s", results[0].Info.Name, results[0].Info.Description)
	})

	t.Run("DetectsStackTrace", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n" +
			"An internal error occurred. stack trace: at main.Handler(server.go:42)"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, scanErr := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, scanErr)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "Stack Trace")
		t.Logf("Finding: %s", results[0].Info.Name)
	})

	t.Run("NoFindingOnCleanResponse", func(t *testing.T) {
		rawReq := "GET /api/health HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\",\"version\":\"1.0.0\"}"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, scanErr := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, scanErr)
		assert.Empty(t, results, "Clean response should produce no findings")
		t.Log("No false positives on clean response — OK")
	})

	t.Run("SkipsTinyResponse", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\n\r\nOK"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, scanErr := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, scanErr)
		assert.Empty(t, results, "Tiny response (<50 chars) should be skipped")
		t.Log("Tiny response skipped — OK")
	})
}

// TestAgentExt_ResponseAnalyzerYAML_GracefulFallbackWithoutLLM verifies that
// the module loads and silently no-ops when LLMClient is nil.
func TestAgentExt_ResponseAnalyzerYAML_GracefulFallbackWithoutLLM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(agentExtensionsDir(), "ai_response_analyzer.vgm.yaml")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, &jsext.EngineOptions{LLMClient: nil})
	require.NoError(t, err)

	passiveMods := engine.PassiveModules()
	require.Len(t, passiveMods, 1, "YAML extension should still load without LLM client")

	rawReq := "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
	rawResp := "HTTP/1.1 500 Internal Server Error\r\n\r\nSQLSTATE[42000]: Syntax error"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	rr := httpmsg.NewHttpRequestResponse(req, resp)

	results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
	require.NoError(t, err)
	assert.Empty(t, results, "Module should silently no-op without LLM client")
	t.Log("Graceful fallback without LLM client — OK")
}

// ── Test: Load all agent extensions ─────────────────────────────────────────

// TestAgentExt_LoadAll verifies that all three agent extensions load correctly
// from the testdata directory into the right module buckets.
func TestAgentExt_LoadAll(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: agentExtensionsDir(),
		Limits:     config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}
	engine := engineWithAgentClient(t, cfg, infra, newXSSMockClient())

	activeMods := engine.ActiveModules()
	passiveMods := engine.PassiveModules()
	postHooks := engine.PostHooks()

	// 1 active:  ai_xss_scanner.js
	assert.Len(t, activeMods, 1, "Should load 1 active module (ai_xss_scanner)")
	// 1 passive: ai_response_analyzer.vgm.yaml (script field)
	assert.Len(t, passiveMods, 1, "Should load 1 passive module (ai_response_analyzer)")
	// 1 post-hook: ai_false_positive_filter.js
	assert.Len(t, postHooks, 1, "Should load 1 post-hook (ai_false_positive_filter)")

	// Verify IDs
	if len(activeMods) > 0 {
		assert.Equal(t, "active-ext-ai-xss-scanner", activeMods[0].ID())
		t.Logf("Active:    %s (%s)", activeMods[0].ID(), activeMods[0].Name())
	}
	if len(passiveMods) > 0 {
		assert.Equal(t, "passive-ext-ai-response-analyzer", passiveMods[0].ID())
		t.Logf("Passive:   %s (%s)", passiveMods[0].ID(), passiveMods[0].Name())
	}
	t.Logf("PostHooks: %d loaded", len(postHooks))
}
