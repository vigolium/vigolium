package mcp_endpoint_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from the given request path,
// extra response headers, and body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("POST " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body
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

// TestScanPerRequest_JSONRPCToolsList drives an MCP path + JSON-RPC 2.0
// envelope carrying a tools/list result, the strongest MCP signal set.
func TestScanPerRequest_JSONRPCToolsList(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"search the web"}]}}`
	ctx := makeHTTPCtx("/mcp", "Content-Type: application/json\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "MCP Server Detected", results[0].Info.Name)
}

// TestScanPerRequest_SessionHeader drives the Mcp-Session-Id response header,
// a strong standalone indicator.
func TestScanPerRequest_SessionHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/v1", "Content-Type: application/json\r\nMcp-Session-Id: sess-xyz\r\n", `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Benign verifies a plain JSON API response yields nothing.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/users", "Content-Type: application/json\r\n", `{"users":[]}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
