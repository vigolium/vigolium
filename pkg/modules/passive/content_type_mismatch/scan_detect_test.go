package content_type_mismatch

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

// makeCtx builds a request/response pair from raw response headers and body.
func makeCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", headers, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_JSONasHTML drives a JSON body served with a text/html
// Content-Type and no nosniff header, which should be flagged as a mismatch.
func TestScanPerRequest_JSONasHTML(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"status": "ok", "items": [1,2,3]}`
	ctx := makeCtx("/api/data", "Content-Type: text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.NotEmpty(t, results[0].ExtractedResults)
	assert.Contains(t, results[0].Info.Description, "application/json")
}

// TestScanPerRequest_HTMLasJSON drives an HTML body served with an
// application/json Content-Type, which should be flagged.
func TestScanPerRequest_HTMLasJSON(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<!DOCTYPE html><html><body>Error page</body></html>`
	ctx := makeCtx("/api/thing", "Content-Type: application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Matching verifies a JSON body served with the correct
// application/json Content-Type produces no findings.
func TestScanPerRequest_Matching(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"status": "ok"}`
	ctx := makeCtx("/api/data", "Content-Type: application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
