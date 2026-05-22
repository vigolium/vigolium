package referrer_policy_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair, optionally setting the
// Referrer-Policy header (omitted when empty).
func makeHTTPCtx(policy string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	if policy != "" {
		rawResp += "Referrer-Policy: " + policy + "\r\n"
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

// TestScanPerHost_WeakPolicy drives an unsafe-url Referrer-Policy (a known weak
// value) and expects a finding.
func TestScanPerHost_WeakPolicy(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("unsafe-url")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "unsafe-url")
}

// TestScanPerHost_MissingPolicy verifies an HTML response with no Referrer-Policy
// header is flagged as missing.
func TestScanPerHost_MissingPolicy(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "missing")
}

// TestScanPerHost_StrongPolicy verifies a hardened no-referrer policy produces
// no findings.
func TestScanPerHost_StrongPolicy(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("no-referrer")
	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
