//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// writeScript is a test helper that writes a JS file to a temp directory.
func writeScript(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

// TestJSExtension_ActiveModule tests that a JS active module is loaded and
// can produce findings when scanning a live target.
func TestJSExtension_ActiveModule(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx := context.Background()

	// Start httpbin container
	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err, "Failed to start httpbin container")
	defer httpbinApp.Stop()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	baseURL := httpbinApp.BaseURL
	host := strings.TrimPrefix(baseURL, "http://")

	// Create a JS active module that uses vigolium.http to probe the target
	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "echo_scanner.js", fmt.Sprintf(`
module.exports = {
  id: "echo-scanner",
  name: "Echo Scanner",
  description: "Detects parameters reflected in response body",
  type: "active",
  severity: "medium",
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    var marker = "VIGOLIUM_CANARY_" + vigolium.utils.randomString(8);
    var built = insertion.buildRequest(marker);

    var resp = vigolium.http.send(built);
    if (!resp || !resp.body) return null;

    if (resp.body.indexOf(marker) !== -1) {
      return [{
        matched: marker,
        url: ctx.request.url,
        name: "Echo Scanner: reflected param " + insertion.name,
        description: "Parameter " + insertion.name + " is reflected in response",
        severity: "medium"
      }];
    }
    return null;
  }
};
`))

	// Initialize engine
	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits: config.ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "ext-echo-scanner", activeMods[0].ID())
	assert.Equal(t, "Echo Scanner", activeMods[0].Name())

	// Scan httpbin /get?search=test — httpbin echoes query params back in JSON
	rawReq := fmt.Sprintf("GET /get?search=test HTTP/1.1\r\nHost: %s\r\n\r\n", host)
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
		results, err := activeMods[0].ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		allResults = append(allResults, results...)
	}

	// httpbin echoes params back in JSON body, so the canary should be found
	require.NotEmpty(t, allResults, "Expected at least one finding from echo scanner")
	assert.Contains(t, allResults[0].Info.Name, "reflected param")
	t.Logf("Active module produced %d findings", len(allResults))
	for _, r := range allResults {
		t.Logf("  Finding: %s (matched: %s)", r.Info.Name, r.Matched)
	}
}

// TestJSExtension_PassiveModule tests that a JS passive module observes
// request/response data and produces findings.
func TestJSExtension_PassiveModule(t *testing.T) {
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

	baseURL := httpbinApp.BaseURL
	host := strings.TrimPrefix(baseURL, "http://")

	// Create a passive module that flags responses missing security headers
	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "missing_headers.js", `
module.exports = {
  id: "missing-security-headers",
  name: "Missing Security Headers",
  description: "Flags responses missing common security headers",
  type: "passive",
  severity: "info",
  scope: "response",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var results = [];
    var required = ["X-Content-Type-Options", "X-Frame-Options"];

    for (var i = 0; i < required.length; i++) {
      var h = required[i];
      if (!ctx.response.headers[h] && !ctx.response.headers[h.toLowerCase()]) {
        results.push({
          matched: ctx.request.url,
          url: ctx.request.url,
          name: "Missing header: " + h,
          description: "Response is missing the " + h + " security header",
          severity: "info"
        });
      }
    }

    return results.length > 0 ? results : null;
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits: config.ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	passiveMods := engine.PassiveModules()
	require.Len(t, passiveMods, 1)
	assert.Equal(t, "ext-missing-security-headers", passiveMods[0].ID())

	// Build a request-response pair with a synthetic response that lacks security headers
	// (matching what httpbin actually returns — no X-Content-Type-Options or X-Frame-Options)
	rawReq := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: httpbin\r\n\r\n{\"args\":{}}"
	rrWithResp := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))

	results, err := passiveMods[0].ScanPerRequest(rrWithResp, infra.ScanCtx)
	require.NoError(t, err)

	// httpbin doesn't set X-Content-Type-Options or X-Frame-Options
	require.NotEmpty(t, results, "Expected passive findings for missing headers")
	t.Logf("Passive module produced %d findings", len(results))
	for _, r := range results {
		t.Logf("  Finding: %s", r.Info.Name)
		assert.Contains(t, r.Info.Name, "Missing header")
	}
}

// TestJSExtension_PreHook tests that a pre-hook can modify requests
// before they reach modules.
func TestJSExtension_PreHook(t *testing.T) {
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

	baseURL := httpbinApp.BaseURL
	host := strings.TrimPrefix(baseURL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	t.Run("ModifyHeaders", func(t *testing.T) {
		// Create a pre-hook that injects an auth header
		scriptDir := t.TempDir()
		writeScript(t, scriptDir, "auth_hook.js", `
module.exports = {
  id: "inject-auth",
  type: "pre_hook",
  description: "Injects authorization header into every request",

  execute: function(request) {
    return {
      headers: {
        "Authorization": "Bearer " + vigolium.config.api_token,
        "X-Injected-By": "pre-hook"
      }
    };
  }
};
`)

		cfg := &config.ExtensionsConfig{
			Enabled:    true,
			ExtensionDir: scriptDir,
			Variables: map[string]string{
				"api_token": "test-token-12345",
			},
			Limits: config.ScriptLimits{
				Timeout:     "30s",
				MaxMemoryMB: 128,
			},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		preHooks := engine.PreHooks()
		require.Len(t, preHooks, 1)

		hookChain := jsext.NewHookChain(preHooks, nil)

		// Create a request and run it through the hook chain
		rawReq := fmt.Sprintf("GET /headers HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		rr := httpmsg.NewHttpRequestResponse(req, nil)

		modified, err := hookChain.RunPreHooks(rr)
		require.NoError(t, err)
		require.NotNil(t, modified, "Pre-hook should return modified request, not nil")

		// Send the modified request to httpbin /headers and check it was injected
		respChain, _, err := infra.HTTPClient.Execute(modified, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		headers := httpbinResp["headers"].(map[string]interface{})
		assert.Equal(t, "Bearer test-token-12345", headers["Authorization"],
			"Authorization header should be injected by pre-hook")
		assert.Equal(t, "pre-hook", headers["X-Injected-By"],
			"Custom header should be injected by pre-hook")
		t.Logf("Pre-hook header injection verified")
	})

	t.Run("SkipRequest", func(t *testing.T) {
		// Create a pre-hook that skips requests to certain paths
		scriptDir := t.TempDir()
		writeScript(t, scriptDir, "skip_hook.js", `
module.exports = {
  id: "skip-static",
  type: "pre_hook",
  description: "Skip requests to static asset paths",

  execute: function(request) {
    if (request.url && request.url.indexOf("/status/") !== -1) {
      return null;  // Skip this request
    }
    return request;  // Pass through
  }
};
`)

		cfg := &config.ExtensionsConfig{
			Enabled:    true,
			ExtensionDir: scriptDir,
			Limits: config.ScriptLimits{
				Timeout:     "30s",
				MaxMemoryMB: 128,
			},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		hookChain := jsext.NewHookChain(engine.PreHooks(), nil)

		// Request to /get should pass through
		rawReq := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		rr := httpmsg.NewHttpRequestResponse(req, nil)

		result, err := hookChain.RunPreHooks(rr)
		require.NoError(t, err)
		assert.NotNil(t, result, "Request to /get should pass through")

		// Request to /status/200 should be skipped
		rawReq2 := fmt.Sprintf("GET /status/200 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req2 := httpmsg.NewHttpRequestWithService(service, []byte(rawReq2))
		rr2 := httpmsg.NewHttpRequestResponse(req2, nil)

		result2, err := hookChain.RunPreHooks(rr2)
		require.NoError(t, err)
		assert.Nil(t, result2, "Request to /status/ should be skipped by pre-hook")
		t.Log("Pre-hook skip behavior verified")
	})
}

// TestJSExtension_PostHook tests that a post-hook can modify or drop results.
func TestJSExtension_PostHook(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	t.Run("EnrichResult", func(t *testing.T) {
		// Post-hook that upgrades severity and adds metadata
		scriptDir := t.TempDir()
		writeScript(t, scriptDir, "enrich_hook.js", `
module.exports = {
  id: "severity-upgrader",
  type: "post_hook",
  description: "Upgrades severity for critical domains",

  execute: function(result) {
    if (result.url && result.url.indexOf("payment") !== -1) {
      return {
        url: result.url,
        matched: result.matched,
        info: {
          name: result.info.name + " [PAYMENT DOMAIN]",
          description: result.info.description,
          severity: "critical"
        }
      };
    }
    return result;
  }
};
`)

		cfg := &config.ExtensionsConfig{
			Enabled:    true,
			ExtensionDir: scriptDir,
			Limits: config.ScriptLimits{
				Timeout:     "30s",
				MaxMemoryMB: 128,
			},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		hookChain := jsext.NewHookChain(nil, engine.PostHooks())

		// Result for a payment URL — should be upgraded
		paymentResult := &output.ResultEvent{
			URL:     "https://payment.example.com/checkout",
			Matched: "sqli detected",
			Info: output.Info{
				Name:        "SQL Injection",
				Description: "Error-based SQLi found",
				Severity:    severity.High,
			},
		}

		modified, err := hookChain.RunPostHooks(paymentResult)
		require.NoError(t, err)
		require.NotNil(t, modified)
		assert.Equal(t, severity.Critical, modified.Info.Severity, "Severity should be upgraded to critical")
		assert.Contains(t, modified.Info.Name, "PAYMENT DOMAIN")
		t.Logf("Enriched result: name=%s severity=%s", modified.Info.Name, modified.Info.Severity)

		// Result for a normal URL — should pass through unchanged
		normalResult := &output.ResultEvent{
			URL:     "https://blog.example.com/search",
			Matched: "xss detected",
			Info: output.Info{
				Name:        "XSS",
				Description: "Reflected XSS found",
				Severity:    severity.Medium,
			},
		}

		passThrough, err := hookChain.RunPostHooks(normalResult)
		require.NoError(t, err)
		require.NotNil(t, passThrough)
		assert.Equal(t, severity.Medium, passThrough.Info.Severity, "Non-payment result should keep original severity")
		t.Log("Pass-through for non-matching result verified")
	})

	t.Run("DropResult", func(t *testing.T) {
		// Post-hook that drops low-severity info findings
		scriptDir := t.TempDir()
		writeScript(t, scriptDir, "filter_hook.js", `
module.exports = {
  id: "drop-info",
  type: "post_hook",
  description: "Drop info-severity findings to reduce noise",

  execute: function(result) {
    if (result.info && result.info.severity === "info") {
      return null;  // Drop this result
    }
    return result;
  }
};
`)

		cfg := &config.ExtensionsConfig{
			Enabled:    true,
			ExtensionDir: scriptDir,
			Limits: config.ScriptLimits{
				Timeout:     "30s",
				MaxMemoryMB: 128,
			},
		}

		engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
		require.NoError(t, err)

		hookChain := jsext.NewHookChain(nil, engine.PostHooks())

		// Info finding should be dropped
		infoResult := &output.ResultEvent{
			URL: "https://example.com",
			Info: output.Info{
				Name:     "Information Disclosure",
				Severity: severity.Info,
			},
		}

		dropped, err := hookChain.RunPostHooks(infoResult)
		require.NoError(t, err)
		assert.Nil(t, dropped, "Info finding should be dropped by post-hook")

		// High finding should survive
		highResult := &output.ResultEvent{
			URL: "https://example.com",
			Info: output.Info{
				Name:     "SQL Injection",
				Severity: severity.High,
			},
		}

		kept, err := hookChain.RunPostHooks(highResult)
		require.NoError(t, err)
		assert.NotNil(t, kept, "High-severity finding should not be dropped")
		t.Log("Post-hook drop behavior verified")
	})
}

// TestJSExtension_ConfigVariables tests that user-defined config variables
// are accessible to JS scripts via vigolium.config.
func TestJSExtension_ConfigVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	// Create a script that reads config variables
	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "config_reader.js", `
module.exports = {
  id: "config-reader",
  name: "Config Reader",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var domain = vigolium.config.collaborator_domain || "";
    var secret = vigolium.config.secret_key || "";

    if (domain === "" || secret === "") {
      return null;
    }

    return [{
      matched: domain + ":" + secret,
      url: ctx.request.url,
      name: "Config variables accessible",
      description: "collaborator=" + domain + " secret=" + secret,
      severity: "info"
    }];
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Variables: map[string]string{
			"collaborator_domain": "collab.test.local",
			"secret_key":         "s3cr3t-v4lu3",
		},
		Limits: config.ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	// Create a minimal request
	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "Script should produce results when config vars are present")

	assert.Contains(t, results[0].Matched, "collab.test.local")
	assert.Contains(t, results[0].Matched, "s3cr3t-v4lu3")
	assert.Contains(t, results[0].Info.Description, "collaborator=collab.test.local")
	t.Logf("Config variables verified: %s", results[0].Info.Description)
}

// TestJSExtension_UtilityAPIs tests the vigolium.utils.* helper functions.
func TestJSExtension_UtilityAPIs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	// Script that exercises various utility functions and returns results
	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "utils_test.js", `
module.exports = {
  id: "utils-tester",
  name: "Utils Tester",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var results = [];

    // Test base64
    var encoded = vigolium.utils.base64Encode("hello world");
    var decoded = vigolium.utils.base64Decode(encoded);
    if (decoded === "hello world") {
      results.push({
        matched: "base64:" + encoded,
        url: ctx.request.url,
        name: "base64 encode/decode OK",
        severity: "info"
      });
    }

    // Test URL encode/decode
    var urlEncoded = vigolium.utils.urlEncode("a=1&b=2");
    var urlDecoded = vigolium.utils.urlDecode(urlEncoded);
    if (urlDecoded === "a=1&b=2") {
      results.push({
        matched: "url:" + urlEncoded,
        url: ctx.request.url,
        name: "URL encode/decode OK",
        severity: "info"
      });
    }

    // Test hashing
    var md5Hash = vigolium.utils.md5("test");
    var sha256Hash = vigolium.utils.sha256("test");
    if (md5Hash.length === 32 && sha256Hash.length === 64) {
      results.push({
        matched: "md5:" + md5Hash + " sha256:" + sha256Hash,
        url: ctx.request.url,
        name: "Hash functions OK",
        severity: "info"
      });
    }

    // Test random string
    var rand1 = vigolium.utils.randomString(16);
    var rand2 = vigolium.utils.randomString(16);
    if (rand1.length === 16 && rand2.length === 16 && rand1 !== rand2) {
      results.push({
        matched: "random:" + rand1,
        url: ctx.request.url,
        name: "Random string OK",
        severity: "info"
      });
    }

    // Test HTML encode/decode
    var htmlEnc = vigolium.utils.htmlEncode('<script>alert(1)</script>');
    var htmlDec = vigolium.utils.htmlDecode(htmlEnc);
    if (htmlDec === '<script>alert(1)</script>') {
      results.push({
        matched: "html:" + htmlEnc,
        url: ctx.request.url,
        name: "HTML encode/decode OK",
        severity: "info"
      });
    }

    return results.length > 0 ? results : null;
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits: config.ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 4, "Expected at least 4 utility test results")

	// Verify each utility worked
	names := make(map[string]bool)
	for _, r := range results {
		names[r.Info.Name] = true
		t.Logf("  Verified: %s (matched: %s)", r.Info.Name, r.Matched)
	}

	assert.True(t, names["base64 encode/decode OK"], "base64 should work")
	assert.True(t, names["URL encode/decode OK"], "URL encode should work")
	assert.True(t, names["Hash functions OK"], "Hash functions should work")
	assert.True(t, names["Random string OK"], "Random string should work")
}

// TestJSExtension_MultipleScripts tests loading multiple scripts of different
// types from the same directory.
func TestJSExtension_MultipleScripts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	scriptDir := t.TempDir()

	writeScript(t, scriptDir, "active1.js", `
module.exports = {
  id: "scanner-a",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return null; }
};
`)

	writeScript(t, scriptDir, "active2.js", `
module.exports = {
  id: "scanner-b",
  type: "active",
  severity: "medium",
  scanTypes: ["per_insertion_point"],
  scanPerInsertionPoint: function(ctx, insertion) { return null; }
};
`)

	writeScript(t, scriptDir, "passive1.js", `
module.exports = {
  id: "observer-a",
  type: "passive",
  severity: "info",
  scope: "response",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return null; }
};
`)

	writeScript(t, scriptDir, "pre_hook1.js", `
module.exports = {
  id: "hook-pre",
  type: "pre_hook",
  execute: function(request) { return request; }
};
`)

	writeScript(t, scriptDir, "post_hook1.js", `
module.exports = {
  id: "hook-post",
  type: "post_hook",
  execute: function(result) { return result; }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits: config.ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	assert.Len(t, engine.ActiveModules(), 2, "Should load 2 active modules")
	assert.Len(t, engine.PassiveModules(), 1, "Should load 1 passive module")
	assert.Len(t, engine.PreHooks(), 1, "Should load 1 pre-hook")
	assert.Len(t, engine.PostHooks(), 1, "Should load 1 post-hook")

	// Verify module IDs
	activeIDs := make(map[string]bool)
	for _, m := range engine.ActiveModules() {
		activeIDs[m.ID()] = true
		t.Logf("Active module: %s", m.ID())
	}
	assert.True(t, activeIDs["ext-scanner-a"])
	assert.True(t, activeIDs["ext-scanner-b"])

	for _, m := range engine.PassiveModules() {
		t.Logf("Passive module: %s", m.ID())
	}
	assert.Equal(t, "ext-observer-a", engine.PassiveModules()[0].ID())
}

// TestJSExtension_DetectAnomaly tests vigolium.utils.detectAnomaly() via inline JS.
func TestJSExtension_DetectAnomaly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "anomaly_test.js", `
module.exports = {
  id: "anomaly-tester",
  name: "Anomaly Tester",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    // Build 4 identical baseline responses + 1 different response
    var baseline = {status: 200, body: "OK", headers: {"content-type": "text/html"}};
    var anomalous = {status: 500, body: "Internal Server Error with a long error message and stack trace", headers: {"content-type": "text/plain"}};
    var responses = [baseline, baseline, baseline, baseline, anomalous];

    var ranked = vigolium.utils.detectAnomaly(responses);
    if (!ranked || ranked.length === 0) return null;

    var results = [];
    for (var i = 0; i < ranked.length; i++) {
      results.push({
        matched: "index:" + ranked[i].index + " score:" + ranked[i].score,
        url: ctx.request.url,
        name: "Anomaly rank " + i + ": index=" + ranked[i].index + " score=" + ranked[i].score,
        severity: "info"
      });
    }
    return results.length > 0 ? results : null;
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits:     config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "detectAnomaly should return ranked results")

	// The anomalous response (index 4) should appear in the ranked list with a score > 0
	foundAnomaly := false
	for _, r := range results {
		t.Logf("  %s (matched: %s)", r.Info.Name, r.Matched)
		if strings.Contains(r.Matched, "index:4") {
			foundAnomaly = true
			// Extract score and verify it's > 0
			assert.NotContains(t, r.Matched, "score:0", "Anomalous response should have non-zero score")
		}
	}
	assert.True(t, foundAnomaly, "The anomalous response (index 4) should appear in results")
}

// TestJSExtension_ExecAPI tests vigolium.utils.exec() via inline JS with AllowExec enabled.
func TestJSExtension_ExecAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "exec_test.js", `
module.exports = {
  id: "exec-tester",
  name: "Exec Tester",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var result = vigolium.utils.exec("echo test123");
    if (!result) return null;

    return [{
      matched: "exitCode:" + result.exitCode + " stdout:" + result.stdout.trim(),
      url: ctx.request.url,
      name: "Exec result",
      description: "stdout=" + result.stdout.trim() + " stderr=" + result.stderr + " exitCode=" + result.exitCode,
      severity: "info"
    }];
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		AllowExec:  true,
		ExtensionDir: scriptDir,
		Limits:     config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "exec() should produce a finding")

	assert.Contains(t, results[0].Matched, "exitCode:0", "echo should exit with code 0")
	assert.Contains(t, results[0].Matched, "stdout:test123", "stdout should contain the echoed string")
	t.Logf("Exec result: %s", results[0].Info.Description)
}

// TestJSExtension_ExecBlocked tests that exec() is blocked when AllowExec is false.
func TestJSExtension_ExecBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "exec_blocked_test.js", `
module.exports = {
  id: "exec-blocked-tester",
  name: "Exec Blocked Tester",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var result = vigolium.utils.exec("echo should_not_run");
    if (!result) return null;

    return [{
      matched: "exitCode:" + result.exitCode,
      url: ctx.request.url,
      name: "Exec blocked result",
      description: "stdout=" + result.stdout + " stderr=" + result.stderr + " exitCode=" + result.exitCode,
      severity: "info"
    }];
  }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		AllowExec:  false, // exec() should be blocked
		ExtensionDir: scriptDir,
		Limits:     config.ScriptLimits{Timeout: "30s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, nil)
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)

	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "exec() should still return a result object even when blocked")

	assert.Contains(t, results[0].Matched, "exitCode:-1", "Blocked exec should return exitCode -1")
	t.Logf("Exec blocked result: %s", results[0].Info.Description)
}
