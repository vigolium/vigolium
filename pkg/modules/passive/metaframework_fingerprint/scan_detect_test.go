package metaframework_fingerprint

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

// TestScanPerRequest_Remix drives the __remixContext body marker, a strong
// Remix fingerprint signal.
func TestScanPerRequest_Remix(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__remixContext = {};</script></html>`
	ctx := makeHTTPCtx("Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Meta-Framework Detected: Remix", results[0].Info.Name)
}

// TestScanPerRequest_Astro drives the <astro-island marker.
func TestScanPerRequest_Astro(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body><astro-island uid="1"></astro-island></body></html>`
	ctx := makeHTTPCtx("Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Meta-Framework Detected: Astro", results[0].Info.Name)
}

// TestScanPerRequest_NonHTML verifies non-HTML content types are skipped.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Content-Type: application/json\r\n", `{"__remixContext":1}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a plain HTML page yields no fingerprint.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Content-Type: text/html\r\n", `<html><body>Hello World</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
