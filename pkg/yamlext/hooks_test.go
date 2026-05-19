package yamlext

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func makeRequest(method, url string) *httpmsg.HttpRequestResponse {
	raw := method + " " + url + " HTTP/1.1\r\nHost: example.com\r\n\r\n"
	svc, _ := httpmsg.ParseService("http://example.com")
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func TestYAMLPreHook_AddHeaders(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-add-headers",
		Type: "pre_hook",
		AddHeaders: map[string]string{
			"X-Custom": "static-value",
		},
	}

	hook := NewYAMLPreHook(def, nil)
	assert.Equal(t, "test-add-headers", hook.ID())

	req := makeRequest("GET", "/api")
	result, err := hook.Execute(req)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify header was added
	rawStr := string(result.Request().Raw())
	assert.Contains(t, rawStr, "X-Custom: static-value")
}

func TestYAMLPreHook_AddHeaders_WithConfig(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-config-headers",
		Type: "pre_hook",
		AddHeaders: map[string]string{
			"Authorization": "Bearer {{config.token}}",
		},
	}

	hook := NewYAMLPreHook(def, map[string]string{"token": "secret123"})
	req := makeRequest("GET", "/api")
	result, err := hook.Execute(req)
	require.NoError(t, err)
	require.NotNil(t, result)

	rawStr := string(result.Request().Raw())
	assert.Contains(t, rawStr, "Authorization: Bearer secret123")
}

func TestYAMLPreHook_SkipExtensions(t *testing.T) {
	def := &ExtensionDef{
		ID:             "test-skip-ext",
		Type:           "pre_hook",
		SkipExtensions: []string{".css", ".js", ".png"},
	}

	hook := NewYAMLPreHook(def, nil)

	// Should skip CSS
	req := makeRequest("GET", "/styles/main.css")
	result, err := hook.Execute(req)
	require.NoError(t, err)
	assert.Nil(t, result, "should skip .css files")

	// Should skip JS
	req = makeRequest("GET", "/scripts/app.js")
	result, err = hook.Execute(req)
	require.NoError(t, err)
	assert.Nil(t, result, "should skip .js files")

	// Should pass through HTML
	req = makeRequest("GET", "/index.html")
	result, err = hook.Execute(req)
	require.NoError(t, err)
	assert.NotNil(t, result, "should pass through .html files")
}

func TestYAMLPreHook_SkipWhen_ConfigEmpty(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-config-empty",
		Type: "pre_hook",
		SkipWhen: &SkipWhenDef{
			ConfigEmpty: "api_key",
		},
		AddHeaders: map[string]string{
			"X-API-Key": "{{config.api_key}}",
		},
	}

	// Config var empty — hook should be skipped (pass through unchanged)
	hook := NewYAMLPreHook(def, map[string]string{})
	req := makeRequest("GET", "/api")
	result, err := hook.Execute(req)
	require.NoError(t, err)
	require.NotNil(t, result)
	rawStr := string(result.Request().Raw())
	assert.NotContains(t, rawStr, "X-API-Key")

	// Config var set — hook should execute
	hook = NewYAMLPreHook(def, map[string]string{"api_key": "key123"})
	result, err = hook.Execute(req)
	require.NoError(t, err)
	require.NotNil(t, result)
	rawStr = string(result.Request().Raw())
	assert.Contains(t, rawStr, "X-API-Key: key123")
}

func TestYAMLPreHook_SkipWhen_URLContains(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-url-skip",
		Type: "pre_hook",
		SkipWhen: &SkipWhenDef{
			URLContains: []string{"/health", "/metrics"},
		},
	}

	hook := NewYAMLPreHook(def, nil)

	// Should skip health endpoint
	req := makeRequest("GET", "/health")
	result, err := hook.Execute(req)
	require.NoError(t, err)
	assert.Nil(t, result, "should skip /health")

	// Should pass through normal endpoints
	req = makeRequest("GET", "/api/users")
	result, err = hook.Execute(req)
	require.NoError(t, err)
	assert.NotNil(t, result, "should pass /api/users through")
}

func TestYAMLPreHook_NilRequest(t *testing.T) {
	def := &ExtensionDef{
		ID:         "test-nil",
		Type:       "pre_hook",
		AddHeaders: map[string]string{"X-Test": "value"},
	}

	hook := NewYAMLPreHook(def, nil)
	result, err := hook.Execute(nil)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// Post-hook tests

func TestYAMLPostHook_Escalate(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-escalate",
		Type: "post_hook",
		Escalate: &EscalateDef{
			WhenURLContains: []string{"admin", "payment"},
			Tag:             "CRITICAL",
			BumpSeverity:    true,
		},
	}

	hook := NewYAMLPostHook(def, nil)
	assert.Equal(t, "test-escalate", hook.ID())

	// Admin URL — should escalate
	result := &output.ResultEvent{
		URL: "https://example.com/admin/dashboard",
		Info: output.Info{
			Name:     "XSS detected",
			Severity: severity.Medium,
		},
	}
	modified, err := hook.Execute(result)
	require.NoError(t, err)
	require.NotNil(t, modified)
	assert.Equal(t, severity.High, modified.Info.Severity, "medium should bump to high")
	assert.True(t, strings.Contains(modified.Info.Name, "[CRITICAL]"))

	// Normal URL — no change
	result2 := &output.ResultEvent{
		URL: "https://example.com/public/page",
		Info: output.Info{
			Name:     "XSS detected",
			Severity: severity.Medium,
		},
	}
	modified2, err := hook.Execute(result2)
	require.NoError(t, err)
	require.NotNil(t, modified2)
	assert.Equal(t, severity.Medium, modified2.Info.Severity)
	assert.Equal(t, "XSS detected", modified2.Info.Name)
}

func TestYAMLPostHook_BumpSeverity_AllLevels(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-bump",
		Type: "post_hook",
		Escalate: &EscalateDef{
			WhenURLContains: []string{"admin"},
			BumpSeverity:    true,
		},
	}
	hook := NewYAMLPostHook(def, nil)

	tests := []struct {
		input    severity.Severity
		expected severity.Severity
	}{
		{severity.Info, severity.Low},
		{severity.Low, severity.Medium},
		{severity.Medium, severity.High},
		{severity.High, severity.Critical},
		{severity.Critical, severity.Critical}, // cap at critical
	}

	for _, tc := range tests {
		result := &output.ResultEvent{
			URL:  "https://example.com/admin",
			Info: output.Info{Severity: tc.input},
		}
		modified, err := hook.Execute(result)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, modified.Info.Severity,
			"expected %s → %s", tc.input, tc.expected)
	}
}

func TestYAMLPostHook_DropWhen_Severity(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-drop-sev",
		Type: "post_hook",
		DropWhen: &DropWhenDef{
			Severity: []string{"info"},
		},
	}
	hook := NewYAMLPostHook(def, nil)

	// Info severity — should be dropped
	result := &output.ResultEvent{
		URL:  "https://example.com/page",
		Info: output.Info{Severity: severity.Info},
	}
	modified, err := hook.Execute(result)
	require.NoError(t, err)
	assert.Nil(t, modified, "info severity should be dropped")

	// Medium severity — should pass through
	result2 := &output.ResultEvent{
		URL:  "https://example.com/page",
		Info: output.Info{Severity: severity.Medium},
	}
	modified2, err := hook.Execute(result2)
	require.NoError(t, err)
	assert.NotNil(t, modified2, "medium severity should pass through")
}

func TestYAMLPostHook_DropWhen_URLContains(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-drop-url",
		Type: "post_hook",
		DropWhen: &DropWhenDef{
			URLContains: []string{"/health", "/status"},
		},
	}
	hook := NewYAMLPostHook(def, nil)

	// Health URL — should be dropped
	result := &output.ResultEvent{URL: "https://example.com/health"}
	modified, err := hook.Execute(result)
	require.NoError(t, err)
	assert.Nil(t, modified)

	// Normal URL — should pass through
	result2 := &output.ResultEvent{URL: "https://example.com/api/users"}
	modified2, err := hook.Execute(result2)
	require.NoError(t, err)
	assert.NotNil(t, modified2)
}

func TestYAMLPostHook_NilResult(t *testing.T) {
	def := &ExtensionDef{
		ID:   "test-nil",
		Type: "post_hook",
		DropWhen: &DropWhenDef{
			Severity: []string{"info"},
		},
	}
	hook := NewYAMLPostHook(def, nil)

	result, err := hook.Execute(nil)
	require.NoError(t, err)
	assert.Nil(t, result)
}
