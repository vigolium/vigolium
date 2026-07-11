package cache_data_leak

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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
	assert.Contains(t, results[0].Info.Name, "Cache Data-Flow Candidate")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

// TestScanPerRequest_NextStaticBundleSkipped is the regression for the reported
// framework-runtime false positive: the Next.js client bundle
// `/_next/static/chunks/main-*.js` ships the string "getStaticProps" plus loose
// tokens like sessionStorage / document.cookie on every Next.js site, so the old
// bare-string pair fired once per host. Server data-fetching code is stripped
// from client bundles, so a match under /_next/static/ must be skipped.
func TestScanPerRequest_NextStaticBundleSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	// Shape of a minified framework bundle: references getStaticProps as machinery
	// and touches sessionStorage / cookies / an Authorization header — none of
	// which is a real server getStaticProps auth fetch.
	body := `t.getStaticProps;var e=window.sessionStorage;document.cookie;h.set("Authorization",x)`
	ctx := makeJSCtx("/hooli-dot-com/_next/static/chunks/main-93dbaebda72da021.js", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a Next.js client build artifact must not be scanned for server caching bugs")
}

// TestScanPerRequest_BundleStringReferenceOnly verifies that even outside
// /_next/static/, a bare "getStaticProps" reference paired with loose tokens
// (sessionStorage, an Authorization header) no longer fires — Pattern 1 now
// requires a getStaticProps definition and a call-shaped server accessor.
func TestScanPerRequest_BundleStringReferenceOnly(t *testing.T) {
	t.Parallel()
	m := New()
	body := `n.getStaticProps&&n.getStaticProps();var s=window.sessionStorage,c=document.cookie;`
	ctx := makeJSCtx("/app.bundle.js", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a bare getStaticProps reference plus loose session tokens is not a real static-generation auth leak")
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
