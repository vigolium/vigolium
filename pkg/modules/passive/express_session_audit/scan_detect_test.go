package express_session_audit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair for the given method/path with the
// supplied Set-Cookie header value (omitted when empty).
func makeHTTPCtx(method, path, setCookie string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n\r\n", method, path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	if setCookie != "" {
		rawResp += fmt.Sprintf("Set-Cookie: %s\r\n", setCookie)
	}
	rawResp += "\r\n<html></html>"
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

// TestScanPerRequest_DefaultSessionName drives the default connect.sid cookie
// name, which is reported on its own.
func TestScanPerRequest_DefaultSessionName(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("POST", "/login", "connect.sid=s%3Aabc.def; Path=/; HttpOnly")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "Default Express Session Name" {
			found = true
		}
	}
	assert.True(t, found, "expected default session name finding")
}

// TestScanPerRequest_ExcessiveExpiry drives a session cookie whose Max-Age far
// exceeds the 7-day threshold.
func TestScanPerRequest_ExcessiveExpiry(t *testing.T) {
	t.Parallel()
	m := New()
	// 30 days in seconds.
	ctx := makeHTTPCtx("POST", "/login", "sessid=abc; Max-Age=2592000; Path=/")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Excessive Session Expiry" {
			found = true
		}
	}
	assert.True(t, found, "expected excessive expiry finding")
}

// TestScanPerRequest_NoCookie verifies a response without Set-Cookie is benign.
func TestScanPerRequest_NoCookie(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("GET", "/about", "")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
