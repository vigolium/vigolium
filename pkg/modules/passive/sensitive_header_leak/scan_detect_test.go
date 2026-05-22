package sensitive_header_leak

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair with the given extra response
// header lines (each must end with \r\n).
func makeHTTPCtx(extraHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + extraHeaders + "\r\n<html></html>"
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

// TestScanPerRequest_AWSKeyHeader drives a custom response header carrying an
// AWS access key ID and expects a leak finding.
func TestScanPerRequest_AWSKeyHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Internal-Token: AKIAIOSFODNN7EXAMPLE\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Sensitive Data in Response Headers", results[0].Info.Name)
}

// TestScanPerRequest_HighEntropyInSuspiciousHeader drives a header whose name
// looks secret-bearing and whose value has high entropy, exercising the entropy
// path.
func TestScanPerRequest_HighEntropyInSuspiciousHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Api-Secret: aZ9kQ2mB7xV4nL1pR8sT3wY6cD0eF5gH\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Benign drives a response with only common safe headers and
// expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Cache-Control: no-cache\r\nX-Request-Id: 12345\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
