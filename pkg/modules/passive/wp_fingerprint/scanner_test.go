package wp_fingerprint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestScanPerRequest_WPContent(t *testing.T) {
	m := New()
	body := `<html><head></head><body>
		<link rel="stylesheet" href="/wp-content/themes/flavor/style.css?ver=1.2.3" />
		<script src="/wp-content/plugins/contact-form-7/assets/js/index.js?ver=5.9.5"></script>
	</body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, ModuleID, r.ModuleID)
	assert.Equal(t, "WordPress Installation Detected", r.Info.Name)
	assert.Contains(t, r.Info.Description, "plugin")
	assert.Contains(t, r.Info.Description, "theme")

	meta := r.Metadata
	plugins, ok := meta["plugins"].([]string)
	require.True(t, ok)
	assert.Contains(t, plugins, "contact-form-7")

	themes, ok := meta["themes"].([]string)
	require.True(t, ok)
	assert.Contains(t, themes, "flavor")
}

func TestScanPerRequest_GeneratorMeta(t *testing.T) {
	m := New()
	body := `<html><head>
		<meta name="generator" content="WordPress 6.4.2" />
	</head><body></body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "6.4.2", r.Metadata["version"])
	assert.Contains(t, r.ExtractedResults, "WordPress 6.4.2")
}

func TestScanPerRequest_RSSFeed(t *testing.T) {
	m := New()
	body := `<?xml version="1.0" encoding="UTF-8"?>
	<rss version="2.0"><channel>
		<generator>https://wordpress.org/?v=6.3.1</generator>
		<link>https://example.com/wp-content/feed/</link>
	</channel></rss>`
	ctx := makeHTTPCtx("/feed/", "application/rss+xml", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "6.3.1", results[0].Metadata["version"])
}

func TestScanPerRequest_NoMatch(t *testing.T) {
	m := New()
	body := `<html><head></head><body><p>Hello world</p></body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NonHTML(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/data", "application/json", `{"wp-content": true}`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_XPingbackHeader(t *testing.T) {
	m := New()
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("wp-test.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Pingback: https://wp-test.com/xmlrpc.php\r\n\r\n<html><body>Simple site</body></html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "WordPress Installation Detected", results[0].Info.Name)
}
