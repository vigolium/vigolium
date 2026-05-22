package laravel_fingerprint

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
	rawReq := []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_TwoSignals drives the laravel_session cookie plus the
// csrf-token meta tag in an HTML body, the minimum 2 signals required.
func TestScanPerRequest_TwoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nSet-Cookie: laravel_session=abc123; path=/\r\n"
	body := `<html><head><meta name="csrf-token" content="tok"></head></html>`
	ctx := makeHTTPCtx("/", headers, body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Laravel Installation Detected", results[0].Info.Name)
}

// TestScanPerRequest_OneSignalInsufficient verifies a single signal does not
// emit a finding (requires 2+).
func TestScanPerRequest_OneSignalInsufficient(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nSet-Cookie: laravel_session=abc123; path=/\r\n"
	ctx := makeHTTPCtx("/", headers, `<html></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a plain response yields no fingerprint.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\nServer: nginx\r\n", `<html><body>Hello</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
