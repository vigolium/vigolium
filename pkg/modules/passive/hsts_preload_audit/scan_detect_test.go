package hsts_preload_audit

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

// makeHTTPCtx builds an HTTPS request/response pair with the given HSTS header
// value (omitted when empty).
func makeHTTPCtx(hsts string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	if hsts != "" {
		rawResp += fmt.Sprintf("Strict-Transport-Security: %s\r\n", hsts)
	}
	rawResp += "\r\n<html>ok</html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerHost_MissingHeader drives an HTTPS HTML response with no HSTS
// header and expects an audit finding listing the missing header.
func TestScanPerHost_MissingHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("")

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerHost_IncompleteHeader drives an HSTS header that lacks
// includeSubDomains and preload and has a short max-age, expecting issues.
func TestScanPerHost_IncompleteHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("max-age=300")

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerHost_PreloadReady drives a fully preload-ready HSTS header and
// expects no findings.
func TestScanPerHost_PreloadReady(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("max-age=63072000; includeSubDomains; preload")

	results, err := m.ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
