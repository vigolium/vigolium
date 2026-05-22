package drupal_fingerprint

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
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_DrupalHeaderAndBody drives a Drupal 8+ install via the
// X-Drupal-Dynamic-Cache header plus core asset paths and a contrib module path,
// the main fingerprinting path including module extraction.
func TestScanPerRequest_DrupalHeaderAndBody(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "X-Drupal-Dynamic-Cache: MISS\r\n"
	body := `<html><script src="/core/misc/drupal.js"></script><link href="/modules/contrib/webform/css/webform.css"></html>`
	ctx := makeHTTPCtx(headers, body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Drupal")
}

// TestScanPerRequest_GeneratorMeta drives detection via the Drupal generator
// meta tag in the body.
func TestScanPerRequest_GeneratorMeta(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)"></head></html>`
	ctx := makeHTTPCtx("", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_Benign verifies a non-Drupal response is not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("", `<html><body>just a site</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
