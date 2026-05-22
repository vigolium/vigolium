package csp_weakness_audit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair with the given
// Content-Security-Policy header (omitted when empty).
func makeHTTPCtx(csp string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	if csp != "" {
		rawResp += fmt.Sprintf("Content-Security-Policy: %s\r\n", csp)
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

// TestScanPerHost_WeakCSP drives a CSP with 'unsafe-inline' in script-src, which
// is the high-severity weakness path, and asserts findings carry this module's ID.
func TestScanPerHost_WeakCSP(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "CSP Weakness: unsafe-inline in Script Source" {
			found = true
		}
	}
	assert.True(t, found, "expected unsafe-inline weakness finding")
}

// TestScanPerHost_StrongCSP drives a hardened CSP defining every directive this
// module checks, so no weakness should be reported.
func TestScanPerHost_StrongCSP(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerHost_NoCSP verifies that an HTML response without a CSP header is
// not flagged (a separate module handles absent CSP).
func TestScanPerHost_NoCSP(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
