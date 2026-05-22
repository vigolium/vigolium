package serialized_object_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeReqCtx builds a request/response pair with the given GET request path+query.
func makeReqCtx(pathQuery string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", pathQuery))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_PHPSerialized drives a request parameter carrying a PHP
// serialized object and expects a finding flagging the format and parameter.
func TestScanPerRequest_PHPSerialized(t *testing.T) {
	t.Parallel()
	m := New()
	// O:8:"stdClass":1:{...} URL-encoded
	ctx := makeReqCtx(`/load?data=O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A3%3A%22bob%22%3B%7D`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "data", results[0].FuzzingParameter)
	assert.Equal(t, "Serialized PHP Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_JavaSerialized drives a Java serialized object (base64
// prefix rO0AB) in a parameter and expects a finding.
func TestScanPerRequest_JavaSerialized(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx(`/load?obj=rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbg`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized Java Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_Benign drives a benign parameter value and expects no
// findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/search?q=hello+world")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
