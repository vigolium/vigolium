package cross_origin_isolation_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// ctxWith builds an HTML request/response pair with the given extra response
// header lines (each "Name: Value") and a Cookie request header when authed.
func ctxWith(respHeaders []string, authCookie bool) *httpmsg.HttpRequestResponse {
	rawReq := "GET /dashboard HTTP/1.1\r\nHost: example.com\r\n"
	if authCookie {
		rawReq += "Cookie: SESSIONID=abc123\r\n"
	}
	rawReq += "\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range respHeaders {
		rawResp += h + "\r\n"
	}
	rawResp += "\r\n<html></html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestFlagsAuthedResponseMissingCOOP(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(nil, true) // authed via Cookie, no COOP/CORP
	res, err := New().ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, res[0].Info.Name, "Cross-Origin Isolation")
}

func TestNoFindingWhenIsolated(t *testing.T) {
	t.Parallel()
	ctx := ctxWith([]string{
		"Cross-Origin-Opener-Policy: same-origin",
		"Cross-Origin-Resource-Policy: same-origin",
	}, true)
	res, err := New().ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestNoFindingWhenUnauthenticated(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(nil, false) // no auth signal
	res, err := New().ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "unauthenticated responses are not the XS-Leaks target")
}
