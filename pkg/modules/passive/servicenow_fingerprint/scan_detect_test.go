package servicenow_fingerprint

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

// TestDetectsServiceNowCookieAndBody fires on a ServiceNow landing page carrying
// a glide_* session cookie and the window.NOW / GlideForm page markers.
func TestDetectsServiceNowCookieAndBody(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head>
<script>window.NOW = {}; var g_form = new GlideForm();</script>
</head><body>ServiceNow Service Portal</body></html>`
	headers := []string{"Set-Cookie: glide_user_route=abc123def456; Path=/; HttpOnly"}
	rr := buildCtx("support.hooli.com", "/sp", headers, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Technology Detected: ServiceNow", res[0].Info.Name)
}

// TestPublishesTechTags asserts the fingerprint marks the host with the full
// tech-stack tag set the servicenow_* active family gates on.
func TestPublishesTechTags(t *testing.T) {
	t.Parallel()
	body := `<script>window.NOW = {glide:true};</script>`
	rr := buildCtx("support.hooli.com", "/sp", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	_, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)

	host := hostOf(t, rr)
	assert.True(t, sc.TechStack.Has(host, "servicenow"), "expected servicenow tag")
	assert.True(t, sc.TechStack.Has(host, "java"), "expected java tag")
}

// TestDetectsVendorHost fires purely on a ServiceNow vendor hostname even when
// the body carries no markers.
func TestDetectsVendorHost(t *testing.T) {
	t.Parallel()
	rr := buildCtx("hooli.service-now.com", "/", nil, "<html><body>ok</body></html>")
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.True(t, sc.TechStack.Has(hostOf(t, rr), "servicenow"))
}

// TestIgnoresUnrelatedStack does not fingerprint a plain HTML page from an
// unrelated Java stack — a bare JSESSIONID cookie is not a ServiceNow signal.
func TestIgnoresUnrelatedStack(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>Acme Intranet</title></head>
<body><div class="content">Welcome</div></body></html>`
	headers := []string{"Set-Cookie: JSESSIONID=9F8A7B6C5D; Path=/; HttpOnly"}
	rr := buildCtx("intranet.acme.com", "/", headers, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "an unrelated Java app must not be fingerprinted as ServiceNow")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "servicenow"))
}

// TestIgnoresCatchAllShell does not fire on a generic SPA/soft-404 shell served
// for an arbitrary deep path.
func TestIgnoresCatchAllShell(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>App</title></head><body><div id="app"></div></body></html>`
	rr := buildCtx("app.globex.com", "/api/now/table/incident", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all shell must not be fingerprinted as ServiceNow")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "servicenow"))
}
