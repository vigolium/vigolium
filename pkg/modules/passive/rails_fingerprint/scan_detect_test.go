package rails_fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from a full raw response string.
func makeHTTPCtx(rawResp string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
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

// TestScanPerRequest_RequestIdRuntime drives the strong X-Request-Id + X-Runtime
// header combination and expects a Rails fingerprint finding from this module.
func TestScanPerRequest_RequestIdRuntime(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Request-Id: abc-123\r\nX-Runtime: 0.0123\r\n\r\n<html>ok</html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Ruby on Rails Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_CSRFMeta drives an HTML body with a Rails CSRF meta tag and
// expects a finding.
func TestScanPerRequest_CSRFMeta(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(`HTTP/1.1 200 OK` + "\r\nContent-Type: text/html\r\n\r\n" + `<meta name="csrf-token" content="x">`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_Benign drives a plain nginx response with no Rails signals
// and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html>hi</html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
