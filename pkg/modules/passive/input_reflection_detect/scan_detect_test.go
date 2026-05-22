package input_reflection_detect

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

func makeHTTPCtx(rawReqLine, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("%s\r\nHost: example.com\r\n\r\n", rawReqLine))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_Reflected drives a request whose query parameter value is
// echoed verbatim into the HTML response body and expects a reflection finding.
func TestScanPerRequest_Reflected(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"text/html",
		`<html><body>Results for hello-world</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].ExtractedResults[0], "q=hello-world")
}

// TestScanPerRequest_NotReflected drives a request whose parameter value does
// NOT appear in the response body and expects no findings.
func TestScanPerRequest_NotReflected(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"text/html",
		`<html><body>No results found</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NumericFilteredOut drives a request whose reflected value
// is all-numeric (filtered) and expects no findings.
func TestScanPerRequest_NumericFilteredOut(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /item?id=123456 HTTP/1.1",
		"text/html",
		`<html><body>Item 123456</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTML drives a JSON response (non-HTML) with a reflected
// value and expects the module to bail out before scanning.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"application/json",
		`{"q":"hello-world"}`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
