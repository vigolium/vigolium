package security_headers_missing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair with the given extra header
// lines (each must end with \r\n) and an optional body.
func makeHTTPCtx(extraHeaders, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	if body == "" {
		body = "<html></html>"
	}
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + extraHeaders + "\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// allHeaders carries every standard security header (and a safe Referrer-Policy /
// cache directive) so a test can opt back into individual gaps.
const allHeaders = "X-Content-Type-Options: nosniff\r\n" +
	"X-Frame-Options: DENY\r\n" +
	"Strict-Transport-Security: max-age=31536000\r\n" +
	"Content-Security-Policy: default-src 'self'\r\n" +
	"Permissions-Policy: geolocation=()\r\n" +
	"Referrer-Policy: no-referrer\r\n" +
	"Cache-Control: no-store\r\n"

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
	ctx := makeHTTPCtx("", "")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "issue(s)")
	assert.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerHost_AllHeadersPresent verifies that a response carrying every
// required header, a safe Referrer-Policy, and a safe Cache-Control produces no
// findings.
func TestScanPerHost_AllHeadersPresent(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(allHeaders, "")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerHost_WeakReferrerPolicy folds in the former referrer-policy-detect
// coverage: a weak Referrer-Policy value is reported even when every other
// header is present.
func TestScanPerHost_WeakReferrerPolicy(t *testing.T) {
	t.Parallel()
	m := New()
	headers := strings.Replace(allHeaders, "Referrer-Policy: no-referrer\r\n", "Referrer-Policy: unsafe-url\r\n", 1)
	ctx := makeHTTPCtx(headers, "")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, strings.Join(results[0].ExtractedResults, "\n"), "unsafe-url")
}

// TestScanPerHost_CacheableSensitiveResponse folds in the former
// cacheable-https-detect coverage: a sensitive HTTPS response (sets a cookie)
// without a safe cache directive is reported.
func TestScanPerHost_CacheableSensitiveResponse(t *testing.T) {
	t.Parallel()
	m := New()
	headers := strings.Replace(allHeaders, "Cache-Control: no-store\r\n", "Cache-Control: public, max-age=3600\r\nSet-Cookie: session=abc123\r\n", 1)
	ctx := makeHTTPCtx(headers, "<html><body>welcome</body></html>")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, strings.Join(results[0].ExtractedResults, "\n"), "Cache-Control")
}

// TestScanPerHost_CacheableSafeDirective verifies a sensitive response carrying
// no-store is not flagged for caching.
func TestScanPerHost_CacheableSafeDirective(t *testing.T) {
	t.Parallel()
	m := New()
	headers := strings.Replace(allHeaders, "Cache-Control: no-store\r\n", "Cache-Control: no-store\r\nSet-Cookie: session=abc123\r\n", 1)
	ctx := makeHTTPCtx(headers, "<html><body>welcome</body></html>")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerHost_NonSensitiveCacheable verifies a non-sensitive HTML response
// (no cookie, no password field) with permissive cache headers is not flagged
// for caching once all other headers are present.
func TestScanPerHost_NonSensitiveCacheable(t *testing.T) {
	t.Parallel()
	m := New()
	headers := strings.Replace(allHeaders, "Cache-Control: no-store\r\n", "Cache-Control: public\r\n", 1)
	ctx := makeHTTPCtx(headers, "<html><body>hello</body></html>")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
