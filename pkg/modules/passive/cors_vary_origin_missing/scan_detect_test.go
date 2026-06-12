package cors_vary_origin_missing

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair. reqOrigin, when non-empty, is sent
// as the request Origin header; respHeaders are appended to the response head.
func makeHTTPCtx(path, reqOrigin string, respHeaders ...string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n", path)
	if reqOrigin != "" {
		rawReq += "Origin: " + reqOrigin + "\r\n"
	}
	rawReq += "\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range respHeaders {
		rawResp += h + "\r\n"
	}
	rawResp += "\r\n<html></html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_ReflectedOriginNoVary is the true positive: the response
// echoes the request Origin into ACAO, credentials are on, and there is no
// Vary: Origin — the cache-poisoning case.
func TestScanPerRequest_ReflectedOriginNoVary(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/api/data", "https://evil.example.com",
		"Access-Control-Allow-Origin: https://evil.example.com",
		"Access-Control-Allow-Credentials: true",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "CORS Missing Vary: Origin", results[0].Info.Name)
}

// TestScanPerRequest_StaticConfigOrigin_NoFinding is the key FP fix: the ACAO is
// a fixed allowed origin that does NOT match the request Origin (statically
// configured, same for everyone) — not a reflection, must not flag.
func TestScanPerRequest_StaticConfigOrigin_NoFinding(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/api/data", "https://attacker.test",
		"Access-Control-Allow-Origin: https://app.example.com",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a fixed (non-reflected) ACAO must not be flagged")
}

// TestScanPerRequest_NoRequestOrigin_NoFinding: without an Origin header on the
// request we cannot observe reflection, so a non-wildcard ACAO is not flagged.
func TestScanPerRequest_NoRequestOrigin_NoFinding(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/api/data", "",
		"Access-Control-Allow-Origin: https://app.example.com",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "no request Origin means reflection cannot be confirmed")
}

// TestScanPerRequest_ReflectedWithVaryOrigin: a reflected ACAO accompanied by
// Vary: Origin is correct and produces no finding.
func TestScanPerRequest_ReflectedWithVaryOrigin(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/api/data", "https://app.example.com",
		"Access-Control-Allow-Origin: https://app.example.com",
		"Vary: Origin",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_WildcardOrigin: wildcard ACAO is ignored.
func TestScanPerRequest_WildcardOrigin(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/api/data", "https://app.example.com",
		"Access-Control-Allow-Origin: *",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_StaticAssetPath_NoFinding: even a reflected ACAO on a
// static-asset route (by path segment) is skipped.
func TestScanPerRequest_StaticAssetPath_NoFinding(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/assets/data", "https://app.example.com",
		"Access-Control-Allow-Origin: https://app.example.com",
	)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
