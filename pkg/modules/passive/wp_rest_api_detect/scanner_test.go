package wp_rest_api_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestScanPerRequest_IndexWithCustomNamespaces(t *testing.T) {
	m := New()
	body := `{
		"name": "Example Site",
		"namespaces": ["wp/v2", "wp-site-health/v1", "oembed/1.0", "contact-form-7/v1", "yoast/v1"]
	}`
	ctx := makeHTTPCtx("/wp-json/", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Contains(t, r.Info.Name, "Namespaces")
	assert.Contains(t, r.Info.Description, "contact-form-7/v1")
	assert.Contains(t, r.Info.Description, "yoast/v1")

	customNS, ok := r.Metadata["customNamespaces"].([]string)
	require.True(t, ok)
	assert.Contains(t, customNS, "contact-form-7/v1")
	assert.Contains(t, customNS, "yoast/v1")
}

func TestScanPerRequest_IndexCoreOnly(t *testing.T) {
	m := New()
	body := `{
		"name": "Example Site",
		"namespaces": ["wp/v2", "wp-site-health/v1", "oembed/1.0"]
	}`
	ctx := makeHTTPCtx("/wp-json/", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	customNS, ok := r.Metadata["customNamespaces"].([]string)
	require.True(t, ok)
	assert.Empty(t, customNS)
}

func TestScanPerRequest_UserExposure(t *testing.T) {
	m := New()
	body := `[
		{"id": 1, "slug": "admin", "name": "Admin User"},
		{"id": 2, "slug": "editor", "name": "Editor"}
	]`
	ctx := makeHTTPCtx("/wp-json/wp/v2/users", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "WordPress Users Exposed via REST API" {
			found = true
			assert.Contains(t, r.Info.Description, "2 user account")
			assert.Contains(t, r.ExtractedResults, "admin (id:1)")
			break
		}
	}
	assert.True(t, found, "expected user exposure finding")
}

func TestScanPerRequest_NonWPJSON(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/v1/data", "application/json", `{"key": "value"}`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NonJSON(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/wp-json/", "text/html", `<html>Not JSON</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}
