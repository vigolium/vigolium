package express_fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from the given status line, extra
// response headers, and body.
func makeHTTPCtx(statusLine, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := statusLine + "\r\n" + headers + "\r\n" + body
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

// TestScanPerRequest_PoweredByExpress drives the X-Powered-By: Express header,
// the strongest Express fingerprint signal.
func TestScanPerRequest_PoweredByExpress(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK", "X-Powered-By: Express\r\nContent-Type: text/html\r\n", "<html></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Express.js Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_NestJSErrorShape drives the default NestJS JSON error shape
// on a 404, exercising the NestJS detection branch.
func TestScanPerRequest_NestJSErrorShape(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"statusCode":404,"message":"Cannot GET /api","error":"Not Found"}`
	ctx := makeHTTPCtx("HTTP/1.1 404 Not Found", "Content-Type: application/json\r\n", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "NestJS Application Detected" {
			found = true
		}
	}
	assert.True(t, found, "expected NestJS finding")
}

// TestScanPerRequest_Benign verifies a plain response yields no fingerprint.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK", "Content-Type: text/html\r\nServer: nginx\r\n", "<html></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
