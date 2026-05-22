package aspnet_viewstate_detect

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

// makeHTMLCtx builds a text/html request/response pair carrying the given body.
func makeHTMLCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_UnencryptedViewState drives a postback form with a valid,
// unencrypted base64 __VIEWSTATE and no EventValidation / anti-CSRF token. This
// exercises the unencrypted, missing-EventValidation, and missing-CSRF paths.
func TestScanPerRequest_UnencryptedViewState(t *testing.T) {
	t.Parallel()
	m := New()
	// Valid base64 that does not start with the encrypted prefixes (/wEP, /wEQ).
	vs := "/wEOFgICtaqCAQK+veGyDVVmd4iZqrvM"
	body := fmt.Sprintf(`<html><form method="post"><input type="hidden" name="__VIEWSTATE" value="%s" /></form></html>`, vs)
	ctx := makeHTMLCtx("/page.aspx", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "ASP.NET ViewState Not Encrypted" {
			found = true
		}
	}
	assert.True(t, found, "expected unencrypted ViewState finding")
}

// TestScanPerRequest_NoViewState verifies a plain HTML page without ViewState
// yields no findings.
func TestScanPerRequest_NoViewState(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTMLCtx("/", `<html><body>Hello World</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTML verifies non-HTML responses are skipped even when
// the body mentions __VIEWSTATE.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"__VIEWSTATE\":\"x\"}"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
