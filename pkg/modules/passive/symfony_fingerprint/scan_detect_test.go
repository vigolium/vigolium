package symfony_fingerprint

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

// makeHTTPCtx builds a request/response pair with extra response headers and a body.
func makeHTTPCtx(extraHeaders, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n%s\r\n%s", extraHeaders, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_PoweredByHeader drives an X-Powered-By header advertising Symfony.
func TestScanPerRequest_PoweredByHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Powered-By: Symfony 6.3\r\n", "<html></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Symfony Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_DebugTokenHeader drives the X-Debug-Token header from the
// Symfony profiler.
func TestScanPerRequest_DebugTokenHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Debug-Token: a1b2c3\r\n", "<html></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_ProfilerBodyMarker drives a body containing a Web Debug Toolbar
// marker when no headers are present.
func TestScanPerRequest_ProfilerBodyMarker(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Cache-Control: no-cache\r\n", `<html><a href="/_profiler/latest">profiler</a></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoSymfony verifies that a non-Symfony response produces no
// findings.
func TestScanPerRequest_NoSymfony(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: nginx\r\n", "<html><body>Hello</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
