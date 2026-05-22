package mixed_content_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTTPS request/response pair from the given path,
// response headers, and HTML body.
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

// TestScanPerRequest_MixedContent drives an HTTPS HTML page referencing an
// http:// script and stylesheet, the core mixed-content trigger.
func TestScanPerRequest_MixedContent(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head>` +
		`<script src="http://cdn.example.com/app.js"></script>` +
		`<link href="http://cdn.example.com/style.css" rel="stylesheet">` +
		`</head></html>`
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerRequest_AllHTTPS verifies a page referencing only https:// assets
// produces no finding.
func TestScanPerRequest_AllHTTPS(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><script src="https://cdn.example.com/app.js"></script></head></html>`
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTML verifies non-HTML content types are skipped.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/data", "Content-Type: application/json\r\n", `{"u":"http://x.com/a.js"}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
