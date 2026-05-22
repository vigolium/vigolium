package javascript_uri_sink

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

func makeHTTPCtx(reqLine, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("%s\r\nHost: example.com\r\n\r\n", reqLine))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestCanProcess_HTML confirms the module only accepts HTML responses.
func TestCanProcess_HTML(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))
	ctx := makeHTTPCtx("GET / HTTP/1.1", "text/html", `<a href="javascript:alert(1)">x</a>`)
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_JSURI drives an HTML response with a javascript: URI in an
// href attribute and expects a sink finding.
func TestScanPerRequest_JSURI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><a href="javascript:alert(document.cookie)">click</a></html>`
	ctx := makeHTTPCtx("GET / HTTP/1.1", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "JavaScript URI Sink", results[0].Info.Name)
}

// TestScanPerRequest_ReflectedParam drives a javascript: sink that reflects a
// request parameter value, raising confidence to Firm.
func TestScanPerRequest_ReflectedParam(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><a href="javascript:runHandler('payloadval')">x</a></html>`
	ctx := makeHTTPCtx("GET /?cb=payloadval HTTP/1.1", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Metadata["reflected_param"] == "cb" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected reflected parameter correlation")
}

// TestScanPerRequest_NoSink drives a benign HTML response with safe links and
// expects no findings.
func TestScanPerRequest_NoSink(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><a href="https://example.com/safe">click</a></html>`
	ctx := makeHTTPCtx("GET / HTTP/1.1", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
