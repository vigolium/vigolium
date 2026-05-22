package api_version_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds a request/response pair with an optional extra response header.
func makeHTTPCtx(path, contentType, extraHeader, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%s\r\n%s", contentType, extraHeader, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_URLVersion drives an /api/v2/ path that carries a version
// segment, which should be detected as a URL-path API version.
func TestScanPerRequest_URLVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/v2/users", "application/json", "", `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "API Version in URL Path" {
			found = true
			assert.Equal(t, ModuleID, r.ModuleID)
		}
	}
	assert.True(t, found, "expected API Version in URL Path finding")
}

// TestScanPerRequest_VersionHeader drives a response carrying an X-API-Version
// header, which should be detected as a version header.
func TestScanPerRequest_VersionHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/data", "application/json", "X-API-Version: 3.1.0\r\n", `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "API Version Header" {
			found = true
		}
	}
	assert.True(t, found, "expected API Version Header finding")
}

// TestScanPerRequest_BodyVersion drives a JSON body containing a version field,
// which should be detected as a response-body API version.
func TestScanPerRequest_BodyVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/status", "application/json", "", `{"version": "1.4.2"}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "API Version in Response Body" {
			found = true
		}
	}
	assert.True(t, found, "expected API Version in Response Body finding")
}

// TestScanPerRequest_NoVersion verifies a benign HTML page with no version
// indicators produces no findings.
func TestScanPerRequest_NoVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/about", "text/html", "", `<html><body>Hello</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
