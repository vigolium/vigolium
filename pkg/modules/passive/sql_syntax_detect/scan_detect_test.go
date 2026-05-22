package sql_syntax_detect

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

// makeHTTPCtx builds a request/response pair with the given request path+query.
func makeHTTPCtx(pathQuery string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", pathQuery))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_SQLStatement drives a request parameter carrying a full SQL
// statement, which should be flagged.
func TestScanPerRequest_SQLStatement(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/search?q=SELECT%20name%20FROM%20users")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "q", results[0].FuzzingParameter)
	assert.Equal(t, "SQL Syntax in Request Parameter", results[0].Info.Name)
}

// TestScanPerRequest_UnionSelect drives a UNION SELECT payload in a parameter.
func TestScanPerRequest_UnionSelect(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/page?id=1%20UNION%20SELECT%20password")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Benign verifies that a benign parameter value produces no
// findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/search?q=hello+world+sentence")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_ShortValue verifies that values below the minimum length are
// ignored even if they contain SQL-like tokens.
func TestScanPerRequest_ShortValue(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/q?x=SELECT")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
