package remix_loader_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair with the given body.
func makeHTTPCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_SensitiveLoaderData drives a Remix context blob carrying an
// API key in loader data and expects an exposure finding from this module.
func TestScanPerRequest_SensitiveLoaderData(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<script>window.__remixContext={"state":{"api_key":"sk_live_0123456789abcdef"}};</script>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Remix Loader Data Exposure", results[0].Info.Name)
}

// TestScanPerRequest_StateBlobOnly drives a Remix manifest blob with no sensitive
// values; the blob detection alone produces a finding.
func TestScanPerRequest_StateBlobOnly(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<script>window.__remixManifest={"routes":{}};</script>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_Benign drives an HTML page with no Remix markers and
// expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("<html><body>Plain page with no remix data</body></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
