package drupal_api_detect

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

// TestScanPerRequest_JSONAPI drives a JSON:API content type plus body structure,
// the primary content-based detection signal.
func TestScanPerRequest_JSONAPI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"jsonapi":{"version":"1.0"},"links":{"self":"/jsonapi/node/article"}}`
	ctx := makeHTTPCtx("/jsonapi/node/article", "application/vnd.api+json", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "JSON:API")
}

// TestScanPerRequest_PathOnly verifies a JSON:API-shaped path with no
// content-based signal is not reported (path-only matches are too generic).
func TestScanPerRequest_PathOnly(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/jsonapi/node", "text/html", `<html>not drupal</html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies an ordinary HTML page is not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "text/html", `<html><body>hello</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
