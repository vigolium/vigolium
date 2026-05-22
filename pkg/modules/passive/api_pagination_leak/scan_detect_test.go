package api_pagination_leak

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

// makeHTTPCtx builds a request/response pair for the given path, content type, and body.
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

// TestScanPerRequest_PaginationLeak drives a JSON response that exposes a total
// record count alongside pagination context, which should trigger a finding.
func TestScanPerRequest_PaginationLeak(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"total_count": 42813, "page": 1, "per_page": 25, "items": []}`
	ctx := makeHTTPCtx("/api/users", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "API Pagination Metadata Exposed", results[0].Info.Name)
}

// TestScanPerRequest_NoContext verifies that a pagination count field without any
// confirming pagination context does not produce a finding (avoids false positives).
func TestScanPerRequest_NoContext(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"count": 12, "data": {"name": "widget"}}`
	ctx := makeHTTPCtx("/api/widget", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonJSON verifies that HTML responses are skipped entirely.
func TestScanPerRequest_NonJSON(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>total_count: 42</body></html>`
	ctx := makeHTTPCtx("/page", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
