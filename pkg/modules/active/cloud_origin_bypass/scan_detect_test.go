package cloud_origin_bypass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// PARTIAL: the final detection step (checkOrigin) fetches the extracted cloud
// storage origin (an s3/gcs/azure host) directly and compares security headers.
// Those hosts cannot be pointed at a loopback httptest server, so end-to-end
// detection is not exercisable here. Coverage targets the construction,
// CanProcess gate, the pure CDN/header/URL-extraction helpers, and the
// early-return branches of ScanPerHost (no CDN, no origin URLs).

// respWith builds an HttpRequestResponse carrying a synthetic response with the
// given raw header block and body, so the response-driven helpers can be tested.
func respWith(t *testing.T, headerBlock, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr := modtest.Request(t, "http://127.0.0.1/")
	raw := "HTTP/1.1 200 OK\r\n" + headerBlock + "\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(raw))
	return httpmsg.NewHttpRequestResponse(rr.Request(), resp)
}

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestCanProcess requires a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))
	assert.False(t, m.CanProcess(modtest.Request(t, "http://127.0.0.1/")), "no response → not processable")
	assert.True(t, m.CanProcess(modtest.Response(modtest.Request(t, "http://127.0.0.1/"), "text/html", "x")))
}

// TestIsCDNPresent detects a CDN from edge headers and the Via header.
func TestIsCDNPresent(t *testing.T) {
	t.Parallel()
	assert.True(t, isCDNPresent(respWith(t, "CF-Ray: abc123\r\n", "body")), "CF-Ray indicates Cloudflare")
	assert.True(t, isCDNPresent(respWith(t, "X-Cache: HIT\r\n", "body")))
	assert.True(t, isCDNPresent(respWith(t, "Via: 1.1 varnish, 1.1 cloudfront\r\n", "body")), "Via cloudfront pattern")
	assert.False(t, isCDNPresent(respWith(t, "Server: nginx\r\n", "body")), "plain origin has no CDN markers")
}

// TestCollectSecurityHeaders gathers only the present security headers.
func TestCollectSecurityHeaders(t *testing.T) {
	t.Parallel()
	got := collectSecurityHeaders(respWith(t,
		"Content-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\n", "body"))
	assert.Equal(t, "default-src 'self'", got["Content-Security-Policy"])
	assert.Equal(t, "DENY", got["X-Frame-Options"])
	_, hasHSTS := got["Strict-Transport-Security"]
	assert.False(t, hasHSTS, "absent header must not appear")
}

// TestExtractOriginURLs pulls cloud-storage origin URLs out of a response body.
func TestExtractOriginURLs(t *testing.T) {
	t.Parallel()
	body := `<img src="https://assets.s3.amazonaws.com/logo.png">
	         <link href="https://storage.googleapis.com/bucket/style.css">
	         <a href="/local/path">x</a>`
	urls := extractOriginURLs(body)
	require.NotEmpty(t, urls)
	assert.Contains(t, urls, "https://assets.s3.amazonaws.com/logo.png")
	assert.Contains(t, urls, "https://storage.googleapis.com/bucket/style.css")

	assert.Empty(t, extractOriginURLs("<a href=\"/relative\">no cloud origins</a>"))
}

// TestScanPerHost_NoCDNEarlyReturn ensures the scan bails when no CDN is
// detected, even though the body contains cloud origin URLs.
func TestScanPerHost_NoCDNEarlyReturn(t *testing.T) {
	t.Parallel()
	rr := respWith(t, "Server: nginx\r\n", `<img src="https://x.s3.amazonaws.com/a.png">`)
	client := modtest.Requester(t)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no CDN present → no scanning, no finding")
}

// TestScanPerHost_NoOriginURLsEarlyReturn ensures the scan bails when a CDN is
// present but the body exposes no cloud-storage origin URLs.
func TestScanPerHost_NoOriginURLsEarlyReturn(t *testing.T) {
	t.Parallel()
	rr := respWith(t, "CF-Ray: deadbeef\r\n", "<html><body>no origins here</body></html>")
	client := modtest.Requester(t)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "CDN but no origin URLs → no finding")
}
