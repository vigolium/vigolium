package nextjs_dynamic_param_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds a request/response pair from the given path, response
// headers, and JS/TS body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body
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

// TestScanPerRequest_SearchParamsAuth drives searchParams used in an auth
// decision with no validation, a high-severity privilege-escalation pattern.
func TestScanPerRequest_SearchParamsAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export function GET(req) { if (searchParams.get('isAdmin') === '1') { return ok; } }`
	ctx := makeHTTPCtx("/route.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "SearchParams in Auth Decision")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

// TestScanPerRequest_ValidatedSkipped verifies that a body with validation
// helpers present is skipped even when params are referenced.
func TestScanPerRequest_ValidatedSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export function GET(req) { const id = parseInt(params.id); db.findUnique({where: params.id}); }`
	ctx := makeHTTPCtx("/route.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies code with no params usage produces no
// finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export function GET() { return Response.json({ ok: true }); }`
	ctx := makeHTTPCtx("/route.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
