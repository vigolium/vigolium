package java_server_fingerprint

import (
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

func makeHTTPCtx(rawRespHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\n" + rawRespHeaders + "\r\n<html>ok</html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_TomcatServer drives a Tomcat Server header and expects a
// specific Java app-server finding tagged with the server.
func TestScanPerRequest_TomcatServer(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: Apache-Coyote/1.1 (Tomcat)\r\nContent-Type: text/html\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Java App Server Detected: tomcat", results[0].Info.Name)
}

// TestScanPerRequest_ServletHeader drives an X-Powered-By: Servlet header and
// expects a generic Java app-server finding.
func TestScanPerRequest_ServletHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Powered-By: Servlet/3.1\r\nContent-Type: text/html\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Java Application Server Detected", results[0].Info.Name)
}

// TestScanPerRequest_JSessionOnly drives a response whose only Java signal is a
// JSESSIONID cookie; the module marks tech but emits no finding for this alone.
func TestScanPerRequest_JSessionOnly(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Set-Cookie: JSESSIONID=ABC123\r\nContent-Type: text/html\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoJava drives a response with no Java signals and expects
// no findings.
func TestScanPerRequest_NoJava(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: nginx/1.21\r\nContent-Type: text/html\r\n")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
