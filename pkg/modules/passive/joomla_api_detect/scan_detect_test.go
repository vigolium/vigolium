package joomla_api_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(path, rawRespHeaders, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", rawRespHeaders, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_APIPath drives a request to /api/index.php returning a
// JSON:API resource structure and expects a Joomla API exposure finding.
func TestScanPerRequest_APIPath(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"links":{"self":"/api/index.php/v1/users"},"data":[]}`
	ctx := makeHTTPCtx("/api/index.php/v1/users", "Content-Type: application/vnd.api+json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Joomla Web Services API Exposure", results[0].Info.Name)
}

// TestScanPerRequest_CORSWideOpen drives a Joomla API endpoint with a wildcard
// CORS header and expects the severity to escalate to Medium.
func TestScanPerRequest_CORSWideOpen(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"/api/index.php/v1/config",
		"Content-Type: application/vnd.api+json\r\nAccess-Control-Allow-Origin: *",
		`{"links":{},"data":{}}`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
}

// TestScanPerRequest_NotJoomlaAPI drives a non-API path and expects no findings
// even though the body looks like a JSON:API document.
func TestScanPerRequest_NotJoomlaAPI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"links":{},"data":[]}`
	ctx := makeHTTPCtx("/index.php", "Content-Type: application/vnd.api+json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
