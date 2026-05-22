package graphql_error_leak

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

func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_FieldSuggestion drives a GraphQL JSON error response that
// leaks a "Did you mean" field suggestion and expects a verbose error finding.
func TestScanPerRequest_FieldSuggestion(t *testing.T) {
	t.Parallel()
	m := New()
	// The raw JSON message starts with the "Did you mean ..." suggestion and
	// contains escaped quotes around the suggested field name.
	body := `{"errors":[{"message":"Did you mean \"email\"?"}]}`
	ctx := makeHTTPCtx("/graphql", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "GraphQL Verbose Error Detected", results[0].Info.Name)
}

// TestScanPerRequest_DatabaseError drives a GraphQL error response that surfaces
// a database/ORM error and expects a finding.
func TestScanPerRequest_DatabaseError(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"errors":[{"message":"SequelizeDatabaseError: relation \"users\" does not exist"}]}`
	ctx := makeHTTPCtx("/api/graphql", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoLeak drives a GraphQL error response with markers but no
// leak patterns and expects no findings.
func TestScanPerRequest_NoLeak(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"errors":[{"message":"Unauthorized"}]}`
	ctx := makeHTTPCtx("/graphql", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonJSON drives a non-JSON content type and expects the
// module to bail out before inspecting the body.
func TestScanPerRequest_NonJSON(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"errors":[{"message":"Cannot query field \"x\" on type \"User\". Did you mean \"y\"?"}]}`
	ctx := makeHTTPCtx("/graphql", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
