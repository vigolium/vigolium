package permissions_policy_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from the given response headers
// and HTML body.
func makeHTTPCtx(headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerHost_WildcardCamera drives a Permissions-Policy header that grants
// camera access to all origins, an overly permissive directive.
func TestScanPerHost_WildcardCamera(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nPermissions-Policy: camera=*, geolocation=(self)\r\n"
	ctx := makeHTTPCtx(headers, `<html></html>`)

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerHost_MissingHeader drives an HTML response with no
// Permissions-Policy/Feature-Policy headers, which is itself flagged.
func TestScanPerHost_MissingHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Content-Type: text/html\r\n", `<html></html>`)

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerHost_NonHTML verifies non-HTML responses are skipped.
func TestScanPerHost_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Content-Type: application/json\r\n", `{}`)

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
