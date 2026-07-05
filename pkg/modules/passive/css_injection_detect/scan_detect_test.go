package css_injection_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func ctx(target, respBody string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", target)
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + respBody
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

func TestFlagsReflectionInStyleBlock(t *testing.T) {
	t.Parallel()
	// theme value reflected inside a <style> block.
	body := `<html><head><style>body{background:` + `aabbccddee` + `}</style></head><body>x</body></html>`
	res, err := New().ScanPerRequest(ctx("/page?theme=aabbccddee", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, res[0].Info.Name, "CSS Injection")
}

func TestNoFindingWhenReflectionOutsideCSS(t *testing.T) {
	t.Parallel()
	// Value reflected only in normal HTML body, not a CSS context.
	body := `<html><body><style>body{color:red}</style><div>aabbccddee</div></body></html>`
	res, err := New().ScanPerRequest(ctx("/page?theme=aabbccddee", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "reflection outside a CSS context must not be flagged here")
}

func TestNoFindingWhenNotReflected(t *testing.T) {
	t.Parallel()
	body := `<html><head><style>body{color:red}</style></head><body>x</body></html>`
	res, err := New().ScanPerRequest(ctx("/page?theme=aabbccddee", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
