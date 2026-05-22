package flask_fingerprint

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

func makeHTTPCtx(rawResp string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ServerHeader drives a response with a Werkzeug Server
// header (strong signal) and expects a Certain-confidence fingerprint finding.
func TestScanPerRequest_ServerHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK\r\nServer: Werkzeug/2.0.1 Python/3.9\r\nContent-Type: text/html\r\n\r\n<html>ok</html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Flask/Werkzeug Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_WerkzeugDebugger drives a response body that exposes the
// Werkzeug Debugger (strong signal) and expects a finding.
func TestScanPerRequest_WerkzeugDebugger(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Type: text/html\r\n\r\n<title>Werkzeug Debugger</title>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Flask/Werkzeug Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_WeakSignals drives an error response carrying two weak
// signals (Jinja2 error + Flask traceback) which together cross the reporting
// threshold.
func TestScanPerRequest_WeakSignals(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Traceback (most recent call last): jinja2.exceptions.TemplateNotFound raised by flask app"
	ctx := makeHTTPCtx(fmt.Sprintf("HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Type: text/html\r\n\r\n%s", body))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoSignals drives a benign response with no Flask signals
// and expects no findings.
func TestScanPerRequest_NoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_SingleWeakSignal drives an error response with only one
// weak signal, which is below the 2-weak-signal threshold, so no finding.
func TestScanPerRequest_SingleWeakSignal(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Type: text/html\r\n\r\njinja2 error only")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
