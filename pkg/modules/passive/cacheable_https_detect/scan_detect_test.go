package cacheable_https_detect

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

// makeHTTPSCtx builds an HTTPS request/response pair from raw response headers and body.
func makeHTTPSCtx(path, respHeaders, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", respHeaders, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_CacheableCookie drives an HTTPS response that sets a cookie
// without any safe cache-control directive, which should be flagged.
func TestScanPerRequest_CacheableCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nSet-Cookie: session=abc123\r\nCache-Control: public, max-age=3600"
	ctx := makeHTTPSCtx("/account", headers, "<html><body>welcome</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerRequest_SafeDirective verifies a sensitive response carrying a
// no-store directive is not flagged.
func TestScanPerRequest_SafeDirective(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nSet-Cookie: session=abc123\r\nCache-Control: no-store"
	ctx := makeHTTPSCtx("/account", headers, "<html><body>welcome</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NotSensitive verifies a non-sensitive HTTPS response (no
// cookie, no password field) yields no findings.
func TestScanPerRequest_NotSensitive(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nCache-Control: public"
	ctx := makeHTTPSCtx("/", headers, "<html><body>Hello</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
