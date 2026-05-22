package software_version_header

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

// makeHTTPCtx builds a request/response pair with optional extra response headers.
func makeHTTPCtx(extraHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n%s\r\nbody", extraHeaders)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ServerVersion drives a Server header carrying an explicit
// version number, which should be flagged.
func TestScanPerRequest_ServerVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: Apache/2.4.41\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Software Version Disclosed in Headers", results[0].Info.Name)
}

// TestScanPerRequest_PoweredByVersion drives an X-Powered-By header with a version.
func TestScanPerRequest_PoweredByVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Powered-By: PHP/8.1.2\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoVersion verifies that a Server header without a version
// number produces no findings.
func TestScanPerRequest_NoVersion(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: nginx\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoHeaders verifies that a response without version-disclosing
// headers produces no findings.
func TestScanPerRequest_NoHeaders(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Cache-Control: no-cache\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
