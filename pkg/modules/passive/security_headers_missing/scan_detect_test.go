package security_headers_missing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair with the given extra header
// lines (each must end with \r\n).
func makeHTTPCtx(extraHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + extraHeaders + "\r\n<html></html>"
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

// TestScanPerHost_MissingHeaders drives an HTML response with no security
// headers and expects a finding listing the missing headers.
func TestScanPerHost_MissingHeaders(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "Missing")
}

// TestScanPerHost_AllHeadersPresent verifies that a response carrying every
// required security header produces no findings.
func TestScanPerHost_AllHeadersPresent(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "X-Content-Type-Options: nosniff\r\n" +
		"X-Frame-Options: DENY\r\n" +
		"Strict-Transport-Security: max-age=31536000\r\n" +
		"Content-Security-Policy: default-src 'self'\r\n" +
		"Permissions-Policy: geolocation=()\r\n"
	ctx := makeHTTPCtx(headers)
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
