package auth_headers_detect

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

// makeReqCtx builds a request/response pair from raw request headers.
func makeReqCtx(path, reqHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n%s\r\n", path, reqHeaders))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_BearerToken drives a request carrying an Authorization
// bearer token, which should be flagged.
func TestScanPerRequest_BearerToken(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/api/profile", "Authorization: Bearer eyJhbGciOiJIUzI1Ni1.payload.sig\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Authorization", results[0].FuzzingParameter)
	require.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerRequest_NoAuth verifies a request without an Authorization header
// produces no findings.
func TestScanPerRequest_NoAuth(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/api/public", "")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_MediaSkipped verifies that media URLs are skipped even when
// they carry an Authorization header.
func TestScanPerRequest_MediaSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/logo.png", "Authorization: Bearer token123\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
