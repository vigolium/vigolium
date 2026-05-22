package joomla_fingerprint

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

func makeHTTPCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_GeneratorTag drives an HTML body with a Joomla generator
// meta tag plus system asset path and expects a CMS fingerprint finding.
func TestScanPerRequest_GeneratorTag(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<head><meta name="generator" content="Joomla! - Open Source Content Management">
		<script src="/media/system/js/core.js"></script></head>`
	ctx := makeHTTPCtx("/", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Joomla")
}

// TestScanPerRequest_Joomla4WithExtensions drives a Joomla 4+ body (api path +
// JS API) referencing a component and expects extension enumeration.
func TestScanPerRequest_Joomla4WithExtensions(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>Joomla.getOptions('csrf.token');</script>
		<link href="/components/com_content/style.css">
		<a href="/api/index.php/v1/articles">api</a></html>`
	ctx := makeHTTPCtx("/", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "4+", results[0].Metadata["generation"])
	exts, ok := results[0].Metadata["extensions"].([]string)
	require.True(t, ok)
	assert.Contains(t, exts, "com_content")
}

// TestScanPerRequest_NotJoomla drives a benign HTML response with no Joomla
// signals and expects no findings.
func TestScanPerRequest_NotJoomla(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", `<html><body>Just a plain page</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
