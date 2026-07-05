package dom_clobbering

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func ctxJS(respBody string) *httpmsg.HttpRequestResponse {
	rawReq := "GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + respBody
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

func TestFlagsSinkFromNamedGlobal(t *testing.T) {
	t.Parallel()
	js := `var s=document.createElement('script'); s.src = window.config; document.body.appendChild(s);`
	res, err := New().ScanPerRequest(ctxJS(js), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, res[0].Info.Name, "DOM Clobbering")
}

func TestNoFindingForStandardProperty(t *testing.T) {
	t.Parallel()
	// Sourcing from a standard DOM property is legitimate, not a clobbering gadget.
	js := `location.href = document.referrer; el.innerHTML = document.title;`
	res, err := New().ScanPerRequest(ctxJS(js), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestNoFindingForPlainCode(t *testing.T) {
	t.Parallel()
	js := `function add(a,b){return a+b;} const x = fetch('/api').then(r=>r.json());`
	res, err := New().ScanPerRequest(ctxJS(js), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
