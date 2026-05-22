package aspnet_fingerprint

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

// makeHTTPCtx builds a request/response pair from raw response headers and a body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", headers, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_AspNetHeaders drives a response with ASP.NET version and
// IIS server headers, which should fingerprint the platform.
func TestScanPerRequest_AspNetHeaders(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Server: Microsoft-IIS/10.0\r\nX-AspNet-Version: 4.0.30319\r\nX-Powered-By: ASP.NET\r\nContent-Type: text/html"
	ctx := makeHTTPCtx("/", headers, "<html></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "ASP.NET/IIS Installation Detected", results[0].Info.Name)
}

// TestScanPerRequest_ViewStateBody drives a Web Forms HTML body containing
// __VIEWSTATE, which should fingerprint ASP.NET Web Forms.
func TestScanPerRequest_ViewStateBody(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><form><input type="hidden" name="__VIEWSTATE" value="abc" /></form></html>`
	ctx := makeHTTPCtx("/page.aspx", "Content-Type: text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_NoSignals verifies that a plain non-ASP.NET response yields
// no findings.
func TestScanPerRequest_NoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "Server: nginx\r\nContent-Type: text/html", "<html><body>Hello</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
