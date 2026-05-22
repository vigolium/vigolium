package nextauth_config_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTTPS request/response pair from the given response
// headers and body.
func makeHTTPCtx(headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/auth/session HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_InsecureCookie drives a NextAuth session cookie missing
// the Secure, HttpOnly, and SameSite attributes on an HTTPS response.
func TestScanPerRequest_InsecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: next-auth.session-token=abc123; Path=/\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "NextAuth.js Insecure Cookie")
}

// TestScanPerRequest_SecureCookie verifies a fully hardened NextAuth cookie
// emits no finding.
func TestScanPerRequest_SecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: __Secure-next-auth.callback-url=https%3A%2F%2Fx; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonNextAuthCookie verifies an unrelated cookie is ignored.
func TestScanPerRequest_NonNextAuthCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: sessionid=xyz; Path=/\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
