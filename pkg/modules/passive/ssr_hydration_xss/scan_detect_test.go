package ssr_hydration_xss

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

// makeHTTPCtx builds an HTML request/response pair with the given path+query and body.
func makeHTTPCtx(pathQuery, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", pathQuery))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ScriptBreakout drives a __NEXT_DATA__ hydration block containing
// an unescaped </script> breakout — the primary XSS vector.
func TestScanPerRequest_ScriptBreakout(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>` +
		`<script id="__NEXT_DATA__">window.__NEXT_DATA__={"q":"x</script ><img src=x onerror=alert(1)>y"}</script>` +
		`</body></html>`
	ctx := makeHTTPCtx("/page", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Script tag breakout in hydration data", results[0].Info.Name)
}

// TestScanPerRequest_UnescapedAngle drives a preloaded-state hydration block with a
// raw < character inside a JSON string value.
func TestScanPerRequest_UnescapedAngle(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__PRELOADED_STATE__={"name":"hello <world tag"}</script></html>`
	ctx := makeHTTPCtx("/dashboard", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, "Unescaped HTML in hydration JSON", results[0].Info.Name)
}

// TestScanPerRequest_SafeHydration verifies that a properly escaped hydration block
// (with < encoding) produces no findings.
func TestScanPerRequest_SafeHydration(t *testing.T) {
	t.Parallel()
	m := New()
	body := "<html><script>window.__PRELOADED_STATE__={\"name\":\"hello \\u003cworld\\u003e\"}</script></html>"
	ctx := makeHTTPCtx("/dashboard", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoHydration verifies that an HTML page without any hydration
// script blocks produces no findings.
func TestScanPerRequest_NoHydration(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "<html><body><p>Hello World</p></body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
