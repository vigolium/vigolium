package nextjs_config_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from the given path, response
// headers, and body.
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

// TestScanPerRequest_ProductionSourceMaps drives a next.config blob enabling
// productionBrowserSourceMaps, a clear misconfiguration pattern.
func TestScanPerRequest_ProductionSourceMaps(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { productionBrowserSourceMaps: true }`
	ctx := makeHTTPCtx("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Production Source Maps")
}

// TestScanPerRequest_WildcardImageHostname drives the SSRF-prone wildcard
// remotePatterns hostname.
func TestScanPerRequest_WildcardImageHostname(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { images: { remotePatterns: [{ hostname: "**" }] } }`
	ctx := makeHTTPCtx("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	found := false
	for _, r := range results {
		if r.Info.Name == "Next.js Config: Wildcard Image Hostname" {
			found = true
		}
	}
	assert.True(t, found, "expected wildcard hostname finding")
}

// TestScanPerRequest_Benign verifies a clean config produces no finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { reactStrictMode: true }`
	ctx := makeHTTPCtx("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
