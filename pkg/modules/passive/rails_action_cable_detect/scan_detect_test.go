package rails_action_cable_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds an HTML request/response pair with the given body.
func makeHTTPCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_ActionCableMeta drives an HTML body with the action-cable-url
// meta tag and expects an Action Cable finding from this module.
func TestScanPerRequest_ActionCableMeta(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(`<meta name="action-cable-url" content="/cable" />`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Rails Action Cable Detected", results[0].Info.Name)
}

// TestScanPerRequest_CableURL drives a body that declares a cable URL via the JS
// config pattern and expects a finding.
func TestScanPerRequest_CableURL(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(`var x = {cableUrl: "wss://example.com/cable"};`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_Benign drives an HTML page with no Action Cable markers
// and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("<html><body>Plain page</body></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
