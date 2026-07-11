package powerpages_fingerprint

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// buildCtx constructs an HttpRequestResponse for host+path with a synthetic 200
// response carrying the given extra response header lines (e.g. Set-Cookie) and
// an HTML body. This mirrors the captured baseline the passive fingerprint reads.
func buildCtx(host, path string, extraHeaders []string, body string) *httpmsg.HttpRequestResponse {
	rawReq := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(host, 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range extraHeaders {
		rawResp += h + "\r\n"
	}
	rawResp += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func hostOf(t *testing.T, rr *httpmsg.HttpRequestResponse) string {
	t.Helper()
	urlx, err := rr.URL()
	require.NoError(t, err)
	return urlx.Host
}

// TestDetectsPowerPagesBody fires on a Power Pages portal shell carrying the
// bundled Web API AJAX wrapper markers and the analytics tracker.
func TestDetectsPowerPagesBody(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head>
<script>var shell = { getTokenDeferred: function(){ return webapi.safeAjax({}); } };</script>
</head><body><script>window.Dynamics365PortalAnalytics = true;</script></body></html>`
	rr := buildCtx("portal.contoso.com", "/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Technology Detected: Microsoft Power Pages", res[0].Info.Name)
}

// TestPublishesTechTags asserts the fingerprint marks the host with the full
// tech-stack tag set the powerpages_* active family gates on.
func TestPublishesTechTags(t *testing.T) {
	t.Parallel()
	body := `<script>shell.getTokenDeferred(); webapi.safeAjax({});</script>`
	rr := buildCtx("portal.contoso.com", "/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	_, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)

	host := hostOf(t, rr)
	assert.True(t, sc.TechStack.Has(host, "powerpages"), "expected powerpages tag")
	assert.True(t, sc.TechStack.Has(host, "dataverse"), "expected dataverse tag")
	assert.True(t, sc.TechStack.Has(host, "aspnet"), "expected aspnet tag")
}

// TestDetectsVendorHost fires purely on a Power Pages vendor hostname even when
// the body carries no markers.
func TestDetectsVendorHost(t *testing.T) {
	t.Parallel()
	rr := buildCtx("contoso.powerappsportals.com", "/", nil, "<html><body>ok</body></html>")
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.True(t, sc.TechStack.Has(hostOf(t, rr), "powerpages"))
}

// TestIgnoresUnrelatedStack does not fingerprint a plain HTML page from an
// unrelated stack, and publishes no tag.
func TestIgnoresUnrelatedStack(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>Acme Blog</title></head>
<body><div class="wp-content">Hello from WordPress</div></body></html>`
	rr := buildCtx("blog.acme.com", "/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "an unrelated stack must not be fingerprinted as Power Pages")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "powerpages"))
}

// TestIgnoresCatchAllShell does not fire on a generic SPA/soft-404 shell served
// for an arbitrary deep path.
func TestIgnoresCatchAllShell(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>App</title></head><body><div id="app"></div></body></html>`
	rr := buildCtx("app.globex.com", "/api/v2/records/12345", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all shell must not be fingerprinted as Power Pages")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "powerpages"))
}
