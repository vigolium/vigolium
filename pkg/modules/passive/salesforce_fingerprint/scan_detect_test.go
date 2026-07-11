package salesforce_fingerprint

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// buildCtx constructs an HttpRequestResponse for host+path with a synthetic 200
// response carrying the given extra response header lines and an HTML body. This
// mirrors the captured baseline the passive fingerprint reads.
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

// TestDetectsSalesforceBody fires on an Experience Cloud / Lightning shell
// carrying Aura framework markers.
func TestDetectsSalesforceBody(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head>
<script>window.Aura = {}; var auraConfig = {"context":{"app":"siteforce:communityApp"}};</script>
</head><body><div data-aura-rendered-by="1:0"></div></body></html>`
	rr := buildCtx("community.globex.com", "/s/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Technology Detected: Salesforce Experience Cloud", res[0].Info.Name)
}

// TestPublishesTechTags asserts the fingerprint marks the host with the full
// tech-stack tag set the salesforce_* active family gates on.
func TestPublishesTechTags(t *testing.T) {
	t.Parallel()
	body := `<script>window.Aura = {}; var config = {"siteforce:communityApp":true};</script>`
	rr := buildCtx("community.globex.com", "/s/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	_, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)

	host := hostOf(t, rr)
	assert.True(t, sc.TechStack.Has(host, "salesforce"), "expected salesforce tag")
	assert.True(t, sc.TechStack.Has(host, "lightning"), "expected lightning tag")
	assert.True(t, sc.TechStack.Has(host, "aura"), "expected aura tag")
}

// TestDetectsVendorHost fires purely on a Salesforce vendor hostname even when
// the body carries no Aura markers.
func TestDetectsVendorHost(t *testing.T) {
	t.Parallel()
	rr := buildCtx("globex.my.salesforce.com", "/", nil, "<html><body>ok</body></html>")
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.True(t, sc.TechStack.Has(hostOf(t, rr), "salesforce"))
}

// TestIgnoresUnrelatedStack does not fingerprint a plain HTML page from an
// unrelated stack, and publishes no tag.
func TestIgnoresUnrelatedStack(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>Initech</title></head>
<body><div class="container">Welcome to our corporate site</div></body></html>`
	rr := buildCtx("www.initech.com", "/", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "an unrelated stack must not be fingerprinted as Salesforce")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "salesforce"))
}

// TestIgnoresCatchAllShell does not fire on a generic SPA/soft-404 shell served
// for an arbitrary deep path.
func TestIgnoresCatchAllShell(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div></body></html>`
	rr := buildCtx("app.acme.com", "/portal/records/9999", nil, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(rr, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all shell must not be fingerprinted as Salesforce")
	assert.False(t, sc.TechStack.Has(hostOf(t, rr), "salesforce"))
}
