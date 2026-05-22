package cors_vary_origin_missing

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair appending extraHeaders to the
// response head.
func makeHTTPCtx(path string, extraHeaders ...string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range extraHeaders {
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

// TestScanPerRequest_DynamicOriginNoVary drives a dynamic (reflected) ACAO with
// credentials enabled but no Vary: Origin header — the cache-poisoning case.
func TestScanPerRequest_DynamicOriginNoVary(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data",
		"Access-Control-Allow-Origin: https://evil.example.com",
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "CORS Missing Vary: Origin", results[0].Info.Name)
}

// TestScanPerRequest_HasVaryOrigin verifies a dynamic ACAO accompanied by
// Vary: Origin produces no finding.
func TestScanPerRequest_HasVaryOrigin(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data",
		"Access-Control-Allow-Origin: https://app.example.com",
		"Vary: Origin",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_WildcardOrigin verifies wildcard ACAO is ignored (this
// module only flags dynamic, non-wildcard origins).
func TestScanPerRequest_WildcardOrigin(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data", "Access-Control-Allow-Origin: *")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
