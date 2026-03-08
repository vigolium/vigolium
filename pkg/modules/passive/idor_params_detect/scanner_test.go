package idor_params_detect

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeHTTPCtx(path, query, contentType, body string) *httpmsg.HttpRequestResponse {
	url := path
	if query != "" {
		url += "?" + query
	}
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", url))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Info, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeBoth, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func TestCanProcess(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))

	// Nil response should fail since scope is Both
	req := httpmsg.NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	assert.False(t, m.CanProcess(ctx))

	// Valid request + response should pass
	ctx = makeHTTPCtx("/api/users", "", "text/html", "<html></html>")
	assert.True(t, m.CanProcess(ctx))
}

func TestScanPerRequest_HighSignalParamPlusInt(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/profile", "user_id=12345", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Equal(t, ModuleID, r.ModuleID)
	assert.Equal(t, "Potential IDOR Parameter", r.Info.Name)
	assert.Equal(t, severity.Info, r.Info.Severity)
	assert.Contains(t, r.FuzzingParameter, "user_id")
	assert.Contains(t, r.ExtractedResults, "user_id=12345")
	assert.Contains(t, r.Info.Tags, "idor")
	assert.Contains(t, r.Info.Tags, "bola")

	meta := r.Metadata
	assert.Equal(t, "sequential-int", meta["id_type"])
	assert.Equal(t, "high", meta["name_signal"])
}

func TestScanPerRequest_MediumSignalPlusInt(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/data", "ref=42", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Equal(t, "medium", r.Metadata["name_signal"])
	totalScore := r.Metadata["total_score"].(int)
	assert.GreaterOrEqual(t, totalScore, 5)
}

func TestScanPerRequest_NoSignalNonID(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/search", "q=hello&page=2", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	// "page=2" has no name signal (0) + sequential int (3) = 3 which meets threshold
	// but "q=hello" has 0+0=0 so it won't appear
	// Filter results that are NOT about "page"
	for _, r := range results {
		assert.NotEqual(t, "q", r.FuzzingParameter)
	}
}

func TestScanPerRequest_PathUsersID(t *testing.T) {
	m := New()
	// /users/123 → path param "2" with value "123", preceded by "users" resource noun
	ctx := makeHTTPCtx("/users/123", "", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	// Find the result for the path param with value 123
	var found bool
	for _, r := range results {
		if r.Metadata["param_value"] == "123" {
			found = true
			assert.Equal(t, "users", r.Metadata["resource_noun"])
			assert.Equal(t, true, r.Metadata["is_path_param"])
			totalScore := r.Metadata["total_score"].(int)
			assert.GreaterOrEqual(t, totalScore, 3)
		}
	}
	assert.True(t, found, "expected a result for path param value=123")
}

func TestScanPerRequest_UUIDParam(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/data", "id=550e8400-e29b-41d4-a716-446655440000", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Equal(t, "uuid-v4", r.Metadata["id_type"])
	assert.Equal(t, "high", r.Metadata["name_signal"])
}

func TestScanPerRequest_StructuredCode(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/order", "order_id=ORD-12345", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Equal(t, "structured-code", r.Metadata["id_type"])
}

func TestScanPerRequest_MediaSkipped(t *testing.T) {
	m := New()
	rawReq := []byte("GET /images/logo.png?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\nPNGDATA"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestScanPerRequest_ExcessiveDataExposure(t *testing.T) {
	m := New()
	jsonBody := `{"user": "john", "email": "john@test.com", "password_hash": "abc123", "is_admin": true}`
	ctx := makeHTTPCtx("/api/user", "", "application/json", jsonBody)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	// Find the excessive data exposure result
	var foundExcessive bool
	for _, r := range results {
		if r.Info.Name == "Excessive Data Exposure" {
			foundExcessive = true
			assert.Equal(t, severity.Low, r.Info.Severity)
			assert.Contains(t, r.Info.Tags, "bopla")
			assert.Contains(t, r.Info.Tags, "excessive-data")
			// Should detect password_hash and is_admin
			assert.GreaterOrEqual(t, len(r.ExtractedResults), 2)
		}
	}
	assert.True(t, foundExcessive, "expected an Excessive Data Exposure finding")
}

func TestScanPerRequest_ExcessiveDataExposure_NoSensitiveFields(t *testing.T) {
	m := New()
	jsonBody := `{"user": "john", "email": "john@test.com", "role": "user"}`
	ctx := makeHTTPCtx("/api/user", "", "application/json", jsonBody)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	for _, r := range results {
		assert.NotEqual(t, "Excessive Data Exposure", r.Info.Name)
	}
}

func TestNormalizePathPattern(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/123/orders/456", "/api/users/{id}/orders/{id}"},
		{"/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{id}"},
		{"/api/status", "/api/status"},
		{"/api/items/ORD-12345/details", "/api/items/{id}/details"},
		{"", ""},
		{"/", "/"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, normalizePathPattern(tc.input), "normalizePathPattern(%q)", tc.input)
	}
}

func TestIsJSONResponse(t *testing.T) {
	assert.True(t, isJSONResponse("application/json"))
	assert.True(t, isJSONResponse("application/json; charset=utf-8"))
	assert.True(t, isJSONResponse("application/vnd.api+json"))
	assert.False(t, isJSONResponse("text/html"))
	assert.False(t, isJSONResponse(""))
}

func TestScanPerRequest_Dedup(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/profile", "user_id=12345", "text/html", "<html></html>")
	scanCtx := &modkit.ScanContext{}

	// First call produces results
	results1, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results1)

	// Second call with nil DedupMgr: no dedup → both return results
	results2, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results2)
}
