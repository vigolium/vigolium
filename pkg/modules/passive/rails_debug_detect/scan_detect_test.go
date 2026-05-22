package rails_debug_detect

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
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_ExceptionPage drives a Rails routing-error exception page
// (both markers present) and expects a finding from this module.
func TestScanPerRequest_ExceptionPage(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("ActionController::RoutingError ... Backtrace shown here")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Rails Debug")
}

// TestScanPerRequest_BetterErrors drives a Better Errors page (Critical) and
// expects a finding.
func TestScanPerRequest_BetterErrors(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("<title>Better Errors</title>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_PathDisclosure drives a body leaking a Rails app path and
// expects a path-disclosure finding.
func TestScanPerRequest_PathDisclosure(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("error in /app/app/controllers/users_controller.rb")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_Benign drives a benign HTML page and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("<html><body>All good</body></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
