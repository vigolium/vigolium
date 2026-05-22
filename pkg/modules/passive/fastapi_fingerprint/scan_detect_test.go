package fastapi_fingerprint

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

// TestScanPerRequest_TwoSignals drives uvicorn Server header plus the FastAPI
// {"detail":...} error shape on a 422, meeting the 2+ signal threshold.
func TestScanPerRequest_TwoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"detail":[{"loc":["body","name"],"msg":"field required"}]}`
	headers := "Server: uvicorn\r\nContent-Type: application/json\r\nx-process-time: 0.0012\r\n"
	ctx := makeHTTPCtx("HTTP/1.1 422 Unprocessable Entity", headers, body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "FastAPI/Starlette Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_SingleSignal drives only the uvicorn Server header, which
// is below the 2+ signal reporting threshold.
func TestScanPerRequest_SingleSignal(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK", "Server: uvicorn\r\nContent-Type: application/json\r\n", `{"ok":true}`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a non-FastAPI response yields no finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK", "Server: nginx\r\nContent-Type: text/html\r\n", "<html></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
