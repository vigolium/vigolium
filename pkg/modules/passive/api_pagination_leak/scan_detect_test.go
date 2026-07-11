package api_pagination_leak

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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
	assert.Equal(t, "Large API Pagination Count Observed", results[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
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

// TestScanPerRequest_SmallCountSkipped is the regression for the public-content
// false positive: a Zendesk-style help-center API returns a full pagination
// envelope (count + page_count + per_page + page) but the collection is tiny
// (5 categories). A count that small discloses nothing business-sensitive, so it
// must be suppressed even though every pagination marker is present.
func TestScanPerRequest_SmallCountSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"categories": [], "count": 5, "page": 1, "per_page": 100, "page_count": 1}`
	ctx := makeHTTPCtx("/api/v2/help_center/en-us/categories", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a tiny public collection count is not a sensitive disclosure")
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

func TestScanPerRequest_InvalidJSONMarkerTextSkipped(t *testing.T) {
	t.Parallel()
	body := `"total_count": 999999, "page": 1, "per_page": 25`
	ctx := makeHTTPCtx("/api/users", "application/json", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "pagination-looking text must parse as JSON")
}
