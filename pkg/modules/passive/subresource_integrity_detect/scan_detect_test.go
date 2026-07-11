package subresource_integrity_detect

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds an HTML request/response pair with the given body.
func makeHTTPCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ExternalScriptNoSRI drives an external script tag without an
// integrity attribute, which should be flagged.
func TestScanPerRequest_ExternalScriptNoSRI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><script src="https://cdn.example.org/lib.js"></script></head></html>`
	ctx := makeHTTPCtx(body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].ExtractedResults[0], "https://cdn.example.org/lib.js")
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestScanPerRequest_ExternalStylesheetNoSRI drives an external stylesheet link
// without an integrity attribute.
func TestScanPerRequest_ExternalStylesheetNoSRI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><link rel="stylesheet" href="https://cdn.example.org/app.css"></head></html>`
	ctx := makeHTTPCtx(body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_WithSRI verifies that an external script carrying an integrity
// attribute is not flagged.
func TestScanPerRequest_WithSRI(t *testing.T) {
	t.Parallel()
	m := New()
	digest := base64.StdEncoding.EncodeToString(make([]byte, 48))
	body := `<html><head><script src="https://cdn.example.org/lib.js" integrity="sha384-` + digest + `"></script></head></html>`
	ctx := makeHTTPCtx(body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_SameOrigin verifies that relative (same-origin) resources are
// not flagged.
func TestScanPerRequest_SameOrigin(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head>` +
		`<script src="/static/app.js"></script>` +
		`<script src="https://example.com/static/absolute.js"></script>` +
		`<link rel="stylesheet alternate" href="//example.com/static/app.css">` +
		`</head></html>`
	ctx := makeHTTPCtx(body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_InvalidIntegrityDoesNotCountAsProtection(t *testing.T) {
	t.Parallel()
	body := `<script src="https://cdn.example.org/lib.js" integrity="sha384-abc"></script>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, strings.Join(results[0].ExtractedResults, "\n"), "invalid integrity")
}

func TestScanPerRequest_NonExecutableScriptTypeIsIgnored(t *testing.T) {
	t.Parallel()
	body := `<script type="application/ld+json" src="https://cdn.example.org/schema.json"></script>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_BaseURLAffectsRelativeOrigin(t *testing.T) {
	t.Parallel()
	body := `<base href="https://cdn.example.org/assets/"><script src="app.js"></script>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "app.js")
}
