package env_secret_exposure

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair for the given path, response
// Content-Type, and body.
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

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func TestCanProcess_TextResponse(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/app.js", "application/javascript", "console.log('hi')")
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_FrameworkSecret drives a NEXT_PUBLIC_* secret embedded in a
// JS bundle, exercising the framework env-var pattern path.
func TestScanPerRequest_FrameworkSecret(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const config = {NEXT_PUBLIC_API_SECRET: "s3cr3tValue12345"};`
	ctx := makeHTTPCtx("/_next/static/chunk.js", "application/javascript", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Env Secret Exposure")
}

// TestScanPerRequest_DotenvFile drives a raw .env file served directly with a
// secret-bearing line, exercising the dotenv detection path.
func TestScanPerRequest_DotenvFile(t *testing.T) {
	t.Parallel()
	m := New()
	body := "DEBUG=true\nSTRIPE_KEY=sk_live_abcdef1234567890\nPORT=3000\n"
	ctx := makeHTTPCtx("/.env", "text/plain", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Env File Secret Exposure", results[0].Info.Name)
}

// TestScanPerRequest_Benign verifies a body without any secret indicators is
// not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>Welcome to the homepage</body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
