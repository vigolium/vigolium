package build_misconfig_detect

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

// makeHTTPCtx builds a request/response pair for the given path, content type, and body.
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

// TestCanProcess_JS verifies a JavaScript content type is accepted.
func TestCanProcess_JS(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/app.js", "application/javascript", "console.log(1)")
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_SourceMaps drives a JS config exposing production source
// maps, which should be flagged as a build misconfiguration.
func TestScanPerRequest_SourceMaps(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { productionBrowserSourceMaps: true, reactStrictMode: false }`
	ctx := makeHTTPCtx("/next.config.js", "application/javascript", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Build Misconfiguration")
}

// TestScanPerRequest_DevStart drives a package.json with a dev-mode start
// script, which should be flagged.
func TestScanPerRequest_DevStart(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"scripts": {"start": "next dev", "build": "next build"}}`
	ctx := makeHTTPCtx("/package.json", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Clean verifies a benign JS config produces no findings.
func TestScanPerRequest_Clean(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { reactStrictMode: true, poweredByHeader: false }`
	ctx := makeHTTPCtx("/next.config.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
