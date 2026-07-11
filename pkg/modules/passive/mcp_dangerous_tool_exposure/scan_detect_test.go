package mcp_dangerous_tool_exposure

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds a request/response pair from the given request path,
// response headers, and body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("POST " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_FlagsDangerousTools groups high-impact tools by capability.
func TestScanPerRequest_FlagsDangerousTools(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"run_command","description":"run a shell command"},` +
		`{"name":"delete_file","description":"delete a file"},` +
		`{"name":"fetch_url","description":"fetch a url"},` +
		`{"name":"execute_query","description":"run raw sql"},` +
		`{"name":"get_secret","description":"read a secret"},` +
		`{"name":"search","description":"search the catalog"}` +
		`]}}`
	ctx := makeHTTPCtx("/mcp", "Content-Type: application/json\r\n", body)

	res, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, "MCP Dangerous Tool Exposure", res[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, res[0].EvidenceGrade)

	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.Contains(t, joined, "code execution")
	assert.Contains(t, joined, "run_command")
	assert.Contains(t, joined, "destructive write/delete")
	assert.Contains(t, joined, "delete_file")
	assert.Contains(t, joined, "outbound fetch (SSRF surface)")
	assert.Contains(t, joined, "raw database/SQL")
	assert.Contains(t, joined, "secret/credential access")
	// The benign tool must not appear.
	assert.NotContains(t, joined, "search")
}

// TestScanPerRequest_BenignToolsNoFinding verifies a server that only exposes
// read/search tools is not flagged (regression against noisy over-flagging).
func TestScanPerRequest_BenignToolsNoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"search_catalog","description":"search"},` +
		`{"name":"list_files","description":"list files in a dir"},` +
		`{"name":"recommend_products","description":"recommend items"},` +
		`{"name":"get_weather","description":"current weather"}` +
		`]}}`
	ctx := makeHTTPCtx("/mcp", "Content-Type: application/json\r\n", body)

	res, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "benign read/search tools must not be flagged")
}

// TestScanPerRequest_NonMCPNoFinding verifies a plain JSON API response yields
// nothing.
func TestScanPerRequest_NonMCPNoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/users", "Content-Type: application/json\r\n", `{"users":[]}`)

	res, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestClassify covers the capability classifier directly.
func TestClassify(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "code execution", classify("exec_python"))
	assert.Equal(t, "destructive write/delete", classify("deleteAccount"))
	assert.Equal(t, "outbound fetch (SSRF surface)", classify("http_request"))
	assert.Equal(t, "raw database/SQL", classify("run_query"))
	assert.Equal(t, "secret/credential access", classify("get_api_key"))
	assert.Equal(t, "", classify("search_query"))
	assert.Equal(t, "", classify("recommend"))
	assert.Equal(t, "", classify("list_files"))
}
