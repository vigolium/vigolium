package wasm_module_detect

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

// makeHTTPCtx builds a request/response pair from raw request and response bytes.
func makeHTTPCtx(path string, rawResp []byte) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse(rawResp)
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_MagicBytes drives a .wasm response whose body begins with the
// WebAssembly magic bytes (\x00asm), which should be flagged as a binary module.
func TestScanPerRequest_MagicBytes(t *testing.T) {
	t.Parallel()
	m := New()
	header := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/wasm\r\n\r\n")
	body := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	rawResp := append(header, body...)
	ctx := makeHTTPCtx("/module.wasm", rawResp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "WebAssembly Binary Module", results[0].Info.Name)
}

// TestScanPerRequest_JSInstantiation drives a JS file containing a WebAssembly
// instantiation call.
func TestScanPerRequest_JSInstantiation(t *testing.T) {
	t.Parallel()
	m := New()
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
		"const mod = await WebAssembly.instantiateStreaming(fetch('m.wasm'));")
	ctx := makeHTTPCtx("/app.js", rawResp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, "WebAssembly Instantiation in JavaScript", results[0].Info.Name)
}

// TestScanPerRequest_NoWasm verifies that plain JS without WebAssembly usage produces
// no findings.
func TestScanPerRequest_NoWasm(t *testing.T) {
	t.Parallel()
	m := New()
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
		"function add(a, b) { return a + b; }")
	ctx := makeHTTPCtx("/util.js", rawResp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
