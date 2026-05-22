package cors_headers_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair where extraHeaders are appended to
// the response head (each "Name: Value" line, terminated by CRLF).
func makeHTTPCtx(path string, extraHeaders ...string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range extraHeaders {
		rawResp += h + "\r\n"
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

// TestScanPerRequest_WildcardWithCredentials drives a wildcard ACAO combined
// with credentials, the most dangerous permissive CORS configuration.
func TestScanPerRequest_WildcardWithCredentials(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data",
		"Access-Control-Allow-Origin: *",
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "Wildcard")
}

// TestScanPerRequest_NullOrigin drives a null ACAO value which should be flagged.
func TestScanPerRequest_NullOrigin(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data", "Access-Control-Allow-Origin: null")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoCORS verifies a response without CORS headers is benign.
func TestScanPerRequest_NoCORS(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
