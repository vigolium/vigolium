package insecure_token_storage

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

// TestCanProcess_JS confirms the module accepts JS responses and rejects nil.
func TestCanProcess_JS(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))
	ctx := makeHTTPCtx("/app.js", "application/javascript", `localStorage.setItem("token", x)`)
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_LocalStorageSetItem drives a JS body that persists an auth
// token in localStorage and expects an insecure storage finding.
func TestScanPerRequest_LocalStorageSetItem(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function login(t){ localStorage.setItem("access_token", t); }`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_AuthHeaderFromStorage drives a JS body reading a token from
// localStorage into an Authorization header and expects a finding.
func TestScanPerRequest_AuthHeaderFromStorage(t *testing.T) {
	t.Parallel()
	m := New()
	body := `xhr.setRequestHeader("Authorization", "Bearer " + localStorage.getItem("jwt"));`
	ctx := makeHTTPCtx("/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoStrayBearerStitch is a regression for the Authorization
// header pattern: an unrelated localStorage.getItem('theme') must NOT be stitched to a
// stray "Bearer" literal elsewhere on the same minified line. Statements are
// semicolon-separated, so the bounded gap should prevent a match.
func TestScanPerRequest_NoStrayBearerStitch(t *testing.T) {
	t.Parallel()
	m := New()
	body := `var s="Bearer token format";initApp();renderHeader();applyTheme();var th=localStorage.getItem("theme");`
	ctx := makeHTTPCtx("/bundle.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoStorage drives benign JS with no token storage and
// expects no findings.
func TestScanPerRequest_NoStorage(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function add(a, b) { return a + b; }`
	ctx := makeHTTPCtx("/util.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
