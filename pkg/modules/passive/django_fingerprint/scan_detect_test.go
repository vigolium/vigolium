package django_fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair from the raw response head
// (extra headers) and body.
func makeHTTPCtx(headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /admin/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + headers + "\r\n" + body
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

// TestScanPerRequest_DjangoSignals drives two independent Django signals
// (csrftoken cookie + csrfmiddlewaretoken hidden field), which meets the 2+
// signal threshold required to report.
func TestScanPerRequest_DjangoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Set-Cookie: csrftoken=abc123; Path=/\r\n"
	body := `<html><form><input type="hidden" name="csrfmiddlewaretoken" value="xyz"></form></html>`
	ctx := makeHTTPCtx(headers, body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Django Application Detected", results[0].Info.Name)
}

// TestScanPerRequest_SingleSignal drives only one weak signal, which falls below
// the 2+ signal reporting threshold and must yield no finding.
func TestScanPerRequest_SingleSignal(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Set-Cookie: sessionid=abc; Path=/\r\n", `<html><body>hi</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoSignals verifies an unrelated response is not flagged.
func TestScanPerRequest_NoSignals(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("", `<html><body>plain page</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
