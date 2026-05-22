package oauth_facebook_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeReqCtx builds a request-only context for the given host and request line.
func makeReqCtx(host, reqLine string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(reqLine + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(host, 443, true),
		rawReq,
	)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_FacebookRedirectURI drives a www.facebook.com OAuth
// request carrying a redirect_uri parameter, the core trigger.
func TestScanPerRequest_FacebookRedirectURI(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("www.facebook.com", "GET /dialog/oauth?client_id=1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "redirect_uri", results[0].FuzzingParameter)
}

// TestScanPerRequest_NotFacebook verifies a redirect_uri on a non-Facebook host
// is ignored.
func TestScanPerRequest_NotFacebook(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("evil.example.com", "GET /oauth?redirect_uri=https%3A%2F%2Fx")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoRedirectParam verifies a Facebook request with no
// redirect parameter is not flagged.
func TestScanPerRequest_NoRedirectParam(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("www.facebook.com", "GET /dialog/oauth?client_id=1&scope=email")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
