package cache_data_leak

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

// makeJSCtx builds a JavaScript request/response pair carrying the given body.
func makeJSCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_StaticPropsAuth drives a bundle that uses getStaticProps
// alongside session/auth access, which should flag cross-user data leakage.
func TestScanPerRequest_StaticPropsAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export async function getStaticProps(ctx) { const s = await getSession(ctx); return { props: { session: s, cookies: ctx.cookies } } }`
	ctx := makeJSCtx("/page.js", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Cache Data Leak")
}

// TestScanPerRequest_Clean verifies a benign static page with no auth access
// produces no findings.
func TestScanPerRequest_Clean(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export async function getStaticProps() { return { props: { title: "Home" } } }`
	ctx := makeJSCtx("/page.js", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestCanProcess_NonJS verifies an HTML response without a JS extension is
// rejected by CanProcess.
func TestCanProcess_NonJS(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)
	assert.False(t, m.CanProcess(ctx))
}
