//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/internal/config"
	httpClient "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// extensionsDir returns the absolute path to the example extensions.
func extensionsDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", "extensions")
}

// --------------------------------------------------------------------------
// Active module: reflected_param_scanner.js
// --------------------------------------------------------------------------

func TestExtExample_ReflectedParamScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx := context.Background()
	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err)
	defer httpbinApp.Stop()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	host := strings.TrimPrefix(httpbinApp.BaseURL, "http://")

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "reflected_param_scanner.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "active-ext-reflected-param", activeMods[0].ID())
	assert.Equal(t, "Reflected Parameter Scanner", activeMods[0].Name())

	// httpbin /get echoes query params back in the JSON body
	rawReq := fmt.Sprintf("GET /get?search=test&page=1 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
	require.NoError(t, err)
	require.NotEmpty(t, ips)

	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	var allResults []*output.ResultEvent
	for _, ip := range ips {
		results, scanErr := activeMods[0].ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, scanErr)
		allResults = append(allResults, results...)
	}

	// httpbin echoes params, so both "search" and "page" should reflect
	require.NotEmpty(t, allResults, "Expected at least one reflected-param finding")
	for _, r := range allResults {
		t.Logf("Finding: %s (matched: %s)", r.Info.Name, r.Matched)
		assert.Contains(t, r.Info.Name, "Reflected parameter:")
	}
}

// --------------------------------------------------------------------------
// Active module: error_pattern_detector.js
// --------------------------------------------------------------------------

func TestExtExample_ErrorPatternDetector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "error_pattern_detector.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "active-ext-error-pattern-detector", activeMods[0].ID())

	t.Run("DetectsPythonTraceback", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n" +
			"Traceback (most recent call last):\n  File \"app.py\", line 42\nValueError: invalid"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "Python traceback")
		t.Logf("Found: %s", results[0].Info.Name)
	})

	t.Run("DetectsJavaStackTrace", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n" +
			"<pre>at com.app.Service.java:123</pre>"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "Java/Kotlin stack trace")
	})

	t.Run("DetectsGoPanic", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n" +
			"goroutine 1 [running]:\nmain.main()\n\t/app/main.go:15"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "Go panic stack trace")
	})

	t.Run("NoFalsePositiveOnCleanResponse", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		assert.Empty(t, results, "Clean response should produce no findings")
	})
}

// --------------------------------------------------------------------------
// Passive module: sensitive_header_leak.js
// --------------------------------------------------------------------------

func TestExtExample_SensitiveHeaderLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "sensitive_header_leak.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	passiveMods := engine.PassiveModules()
	require.Len(t, passiveMods, 1)
	assert.Equal(t, "passive-ext-sensitive-header-leak", passiveMods[0].ID())

	t.Run("DetectsXPoweredBy", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: text/html\r\n\r\nOK"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "X-Powered-By")
		assert.Equal(t, severity.Info, results[0].Info.Severity)
		t.Logf("Found: %s", results[0].Info.Name)
	})

	t.Run("DetectsServerVersion", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\nContent-Type: text/html\r\n\r\nOK"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Contains(t, results[0].Info.Name, "Server version")
		assert.Equal(t, severity.Low, results[0].Info.Severity)
	})

	t.Run("NoFindingOnCleanHeaders", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nOK"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, err)
		assert.Empty(t, results, "Clean headers should produce no findings")
	})
}

// --------------------------------------------------------------------------
// Pre-hook: add_auth_header.js
// --------------------------------------------------------------------------

func TestExtExample_AddAuthHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx := context.Background()
	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err)
	defer httpbinApp.Stop()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	host := strings.TrimPrefix(httpbinApp.BaseURL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	t.Run("InjectsAuthAndCorrelationID", func(t *testing.T) {
		cfg := &config.ExtensionsConfig{
			Enabled: true,
			CustomDir: []string{filepath.Join(extensionsDir(), "add_auth_header.js")},
			Variables: map[string]string{
				"auth_token": "my-secret-jwt-token",
			},
			Limits: config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		preHooks := engine.PreHooks()
		require.Len(t, preHooks, 1)
		hookChain := jsext.NewHookChain(preHooks, nil)

		rawReq := fmt.Sprintf("GET /headers HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		rr := httpmsg.NewHttpRequestResponse(req, nil)

		modified, err := hookChain.RunPreHooks(rr)
		require.NoError(t, err)
		require.NotNil(t, modified)

		// Send to httpbin /headers to verify injection
		respChain, _, err := infra.HTTPClient.Execute(modified, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal(respChain.Body().Bytes(), &httpbinResp))
		headers := httpbinResp["headers"].(map[string]interface{})

		assert.Equal(t, "Bearer my-secret-jwt-token", headers["Authorization"])
		corrID, ok := headers["X-Correlation-Id"]
		assert.True(t, ok, "X-Correlation-ID should be present")
		assert.Len(t, corrID, 12, "Correlation ID should be 12 chars")
		t.Logf("Auth header injected, correlation ID: %s", corrID)
	})

	t.Run("PassesThroughWithoutToken", func(t *testing.T) {
		cfg := &config.ExtensionsConfig{
			Enabled: true,
			CustomDir: []string{filepath.Join(extensionsDir(), "add_auth_header.js")},
			// No auth_token variable set
			Limits: config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		hookChain := jsext.NewHookChain(engine.PreHooks(), nil)

		rawReq := fmt.Sprintf("GET /headers HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		rr := httpmsg.NewHttpRequestResponse(req, nil)

		modified, err := hookChain.RunPreHooks(rr)
		require.NoError(t, err)
		require.NotNil(t, modified, "Request should pass through when no token configured")

		// Verify no auth header was added
		respChain, _, err := infra.HTTPClient.Execute(modified, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal(respChain.Body().Bytes(), &httpbinResp))
		headers := httpbinResp["headers"].(map[string]interface{})

		_, hasAuth := headers["Authorization"]
		assert.False(t, hasAuth, "No Authorization header should be added when token is empty")
	})
}

// --------------------------------------------------------------------------
// Pre-hook: skip_static_assets.js
// --------------------------------------------------------------------------

func TestExtExample_SkipStaticAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "skip_static_assets.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	hookChain := jsext.NewHookChain(engine.PreHooks(), nil)

	tests := []struct {
		path     string
		expected bool // true = should pass through, false = should be skipped
	}{
		{"/api/users", true},
		{"/login", true},
		{"/search?q=test", true},
		{"/assets/style.css", false},
		{"/js/app.js", false},
		{"/images/logo.png", false},
		{"/images/photo.jpg", false},
		{"/favicon.ico", false},
		{"/fonts/roboto.woff2", false},
		{"/bundle.js.map", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tt.path)
			req := httpmsg.NewHttpRequest([]byte(rawReq))
			rr := httpmsg.NewHttpRequestResponse(req, nil)

			result, err := hookChain.RunPreHooks(rr)
			require.NoError(t, err)

			if tt.expected {
				assert.NotNil(t, result, "Request to %s should pass through", tt.path)
			} else {
				assert.Nil(t, result, "Request to %s should be skipped", tt.path)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Post-hook: tag_critical_domains.js
// --------------------------------------------------------------------------

func TestExtExample_TagCriticalDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "tag_critical_domains.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	hookChain := jsext.NewHookChain(nil, engine.PostHooks())

	t.Run("EscalatesPaymentDomain", func(t *testing.T) {
		result := &output.ResultEvent{
			URL:     "https://payment.example.com/process",
			Matched: "sqli detected",
			Info: output.Info{
				Name:        "SQL Injection",
				Description: "Error-based SQL injection",
				Severity:    severity.High,
			},
		}

		modified, err := hookChain.RunPostHooks(result)
		require.NoError(t, err)
		require.NotNil(t, modified)
		assert.Equal(t, severity.Critical, modified.Info.Severity)
		assert.Contains(t, modified.Info.Name, "[CRITICAL: payment]")
		t.Logf("Escalated: %s -> %s", "high", modified.Info.Severity)
	})

	t.Run("EscalatesAdminDomain", func(t *testing.T) {
		result := &output.ResultEvent{
			URL:     "https://admin.internal.corp/dashboard",
			Matched: "xss reflected",
			Info: output.Info{
				Name:        "XSS",
				Description: "Reflected cross-site scripting",
				Severity:    severity.Medium,
			},
		}

		modified, err := hookChain.RunPostHooks(result)
		require.NoError(t, err)
		require.NotNil(t, modified)
		assert.Equal(t, severity.High, modified.Info.Severity)
		assert.Contains(t, modified.Info.Name, "[CRITICAL: admin]")
	})

	t.Run("NoChangeForNormalDomain", func(t *testing.T) {
		result := &output.ResultEvent{
			URL:     "https://blog.example.com/post/123",
			Matched: "info leak",
			Info: output.Info{
				Name:        "Information Disclosure",
				Description: "Version info leaked",
				Severity:    severity.Info,
			},
		}

		modified, err := hookChain.RunPostHooks(result)
		require.NoError(t, err)
		require.NotNil(t, modified)
		assert.Equal(t, severity.Info, modified.Info.Severity)
		assert.Equal(t, "Information Disclosure", modified.Info.Name)
	})
}

// --------------------------------------------------------------------------
// Integration: Load all example extensions at once
// --------------------------------------------------------------------------

func TestExtExample_LoadAllExtensions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: extensionsDir(),
		Limits:     config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	passiveMods := engine.PassiveModules()
	preHooks := engine.PreHooks()
	postHooks := engine.PostHooks()

	// 6 active: reflected_param_scanner + error_pattern_detector + anomaly_detector + exec_recon + error_pattern_detector (YAML) + reflected_param (YAML)
	assert.Len(t, activeMods, 6, "Should load 6 active modules")
	// 5 passive: sensitive_header_leak + utils_demo + anomaly_baseline + ai_response_analyzer (YAML) + sensitive_header_leak (YAML)
	assert.Len(t, passiveMods, 5, "Should load 5 passive modules")
	// 4 pre-hooks: add_auth_header + skip_static_assets + add_auth_header (YAML) + skip_static_assets (YAML)
	assert.Len(t, preHooks, 4, "Should load 4 pre-hooks")
	// 2 post-hooks: tag_critical_domains + tag_critical_domains (YAML)
	assert.Len(t, postHooks, 2, "Should load 2 post-hooks")

	// Log all loaded extensions
	for _, m := range activeMods {
		t.Logf("Active:  %s (%s)", m.ID(), m.Name())
	}
	for _, m := range passiveMods {
		t.Logf("Passive: %s (%s)", m.ID(), m.Name())
	}
	t.Logf("Pre-hooks:  %d loaded", len(preHooks))
	t.Logf("Post-hooks: %d loaded", len(postHooks))
}

// --------------------------------------------------------------------------
// Active module: exec_recon.js
// --------------------------------------------------------------------------

func TestExtExample_ExecRecon(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled:   true,
		AllowExec: true,
		CustomDir:   []string{filepath.Join(extensionsDir(), "exec_recon.js")},
		Limits:    config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "active-ext-exec-recon", activeMods[0].ID())
	assert.Equal(t, "DNS Recon via Exec", activeMods[0].Name())

	t.Run("RunsDNSLookup", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		rr := httpmsg.NewHttpRequestResponse(req, nil)

		results, err := activeMods[0].ScanPerHost(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)

		// dig/nslookup may not be available in all environments
		if len(results) > 0 {
			assert.Contains(t, results[0].Info.Name, "DNS records for example.com")
			t.Logf("DNS lookup result: %s", results[0].Info.Description)
		} else {
			t.Log("No DNS results (dig/nslookup may not be available)")
		}
	})
}

// --------------------------------------------------------------------------
// Passive module: anomaly_baseline.js
// --------------------------------------------------------------------------

func TestExtExample_AnomalyBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{filepath.Join(extensionsDir(), "anomaly_baseline.js")},
		Limits:  config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	passiveMods := engine.PassiveModules()
	require.Len(t, passiveMods, 1)
	assert.Equal(t, "passive-ext-anomaly-baseline", passiveMods[0].ID())

	t.Run("DetectsAnomalousResponse", func(t *testing.T) {
		// A 500 error response with large body should differ significantly from 200/OK baseline
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><h1>500 Internal Server Error</h1><p>Something went terribly wrong on the server side</p></body></html>"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, err)
		require.NotEmpty(t, results, "A 500 error response should trigger anomaly detection against 200/OK baseline")
		assert.Contains(t, results[0].Info.Name, "deviates from baseline")
		t.Logf("Anomaly detected: %s (matched: %s)", results[0].Info.Name, results[0].Matched)
	})

	t.Run("NormalResponseNoAnomaly", func(t *testing.T) {
		// A normal 200/OK response should NOT trigger anomaly detection
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nOK"
		req := httpmsg.NewHttpRequest([]byte(rawReq))
		resp := httpmsg.NewHttpResponse([]byte(rawResp))
		rr := httpmsg.NewHttpRequestResponse(req, resp)

		results, err := passiveMods[0].ScanPerRequest(rr, infra.ScanCtx)
		require.NoError(t, err)
		assert.Empty(t, results, "A normal 200/OK response should not trigger anomaly detection")
	})
}
