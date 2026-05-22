package spring_fingerprint

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

// makeHTTPCtx builds a request/response pair with extra response headers and a body.
func makeHTTPCtx(extraHeaders, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%s\r\n%s", contentType, extraHeaders, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_AppContextHeader drives an X-Application-Context header that is
// Spring Boot specific.
func TestScanPerRequest_AppContextHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Application-Context: application:8080\r\n", "text/html", "<html></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Spring Boot/Spring MVC Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_WhitelabelErrorPage drives the Spring Boot default Whitelabel
// Error Page body marker.
func TestScanPerRequest_WhitelabelErrorPage(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: Apache-Coyote/1.1\r\n", "text/html",
		"<html><body><h1>Whitelabel Error Page</h1></body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Metadata, "server")
}

// TestScanPerRequest_NoSpring verifies that a non-Spring response produces no findings.
func TestScanPerRequest_NoSpring(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Server: nginx\r\n", "text/html", "<html><body>Hello</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
