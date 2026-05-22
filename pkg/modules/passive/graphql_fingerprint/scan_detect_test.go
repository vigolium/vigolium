package graphql_fingerprint

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

// TestScanPerRequest_PathMatch drives a request to a /graphql path and expects
// the endpoint to be fingerprinted from the URL path alone.
func TestScanPerRequest_PathMatch(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/graphql", "text/html", "<html>ok</html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "GraphQL Endpoint Detected", results[0].Info.Name)
}

// TestScanPerRequest_BodyShape drives a non-graphql path but a JSON body with
// the GraphQL errors[].locations shape and expects detection from the body.
func TestScanPerRequest_BodyShape(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"errors":[{"message":"oops","locations":[{"line":1,"column":2}]}]}`
	ctx := makeHTTPCtx("/q", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoSignal drives a benign request/response with neither a
// graphql path nor a graphql body shape and expects no findings.
func TestScanPerRequest_NoSignal(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/users", "application/json", `{"data":[1,2,3]}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
