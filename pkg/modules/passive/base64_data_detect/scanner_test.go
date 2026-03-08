package base64_data_detect

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeHTTPCtx(url, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", url))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func makeHTTPCtxWithReqBody(url, reqBody, respBody string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", url, reqBody))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", respBody)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Info, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeBoth, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func TestCanProcess_Nil(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))
}

func findResultBySource(results []*output.ResultEvent, source string) *output.ResultEvent {
	for _, r := range results {
		for _, e := range r.ExtractedResults {
			if e == source {
				return r
			}
		}
	}
	return nil
}

func TestScanPerRequest_JSONBase64InResponse(t *testing.T) {
	m := New()
	// eyJ = base64 for '{"'
	body := `<input value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">`
	ctx := makeHTTPCtx("/page", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	respResult := findResultBySource(results, "Source: response")
	require.NotNil(t, respResult)
	assert.Equal(t, ModuleID, respResult.ModuleID)
	assert.Equal(t, "Base64 Encoded Data in Response", respResult.Info.Name)
	assert.Contains(t, respResult.Info.Tags, "base64")
}

func TestScanPerRequest_PHPArrayInResponse(t *testing.T) {
	m := New()
	// YTo = base64 for 'a:' (PHP serialized array)
	body := `data=YToxOntzOjQ6InRlc3QiO3M6NToidmFsdWUiO30=`
	ctx := makeHTTPCtx("/api", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_PHPObjectInResponse(t *testing.T) {
	m := New()
	// Tzo = base64 for 'O:' (PHP serialized object)
	body := `cookie=TzoxMDoiUGhwT2JqZWN0IjoxOntzOjQ6InRlc3QiO3M6NToidmFsdWUiO30=`
	ctx := makeHTTPCtx("/api", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_JavaSerializedInResponse(t *testing.T) {
	m := New()
	// rO0 = Java serialized object prefix
	body := `session=rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtA=`
	ctx := makeHTTPCtx("/api", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_HTTPSURLInResponse(t *testing.T) {
	m := New()
	// aHR0cHM6L = base64 for 'https:/'
	body := `redirect=aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg==`
	ctx := makeHTTPCtx("/redirect", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_Base64InRequest(t *testing.T) {
	m := New()
	reqBody := "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	ctx := makeHTTPCtxWithReqBody("/api/auth", reqBody, "OK")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	reqResult := findResultBySource(results, "Source: request")
	require.NotNil(t, reqResult, "should detect base64 in request")
	assert.Equal(t, "Base64 Encoded Data in Request", reqResult.Info.Name)
}

func TestScanPerRequest_NoMatch(t *testing.T) {
	m := New()
	body := `<html><body>Hello world</body></html>`
	ctx := makeHTTPCtx("/page", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_MediaURL(t *testing.T) {
	m := New()
	body := `eyJhbGciOiJIUzI1NiJ9`
	ctx := makeHTTPCtx("/image.png", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NilResponse(t *testing.T) {
	m := New()
	rawReq := []byte("GET /page?data=eyJhbGciOiJIUzI1NiJ9 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	ctx := httpmsg.NewHttpRequestResponse(req, nil)

	// Module scope is Both, so CanProcess returns false when response is nil
	assert.False(t, m.CanProcess(ctx))
}

func TestIdentifyPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"eyJhbGciOiJIUzI1NiJ9", "JSON object"},
		{"YToxOntzOjQ6InRlc3QiO30=", "PHP serialized array"},
		{"TzoxMDoiUGhwT2JqZWN0Ijo=", "PHP serialized object"},
		{"PD94bWwgdmVyc2lvbj0=", "PHP tag"},
		{"PD8=", "XML declaration"},
		{"aHR0cHM6Ly9leGFtcGxlLmNvbQ==", "HTTPS URL"},
		{"aHR0cDovL2V4YW1wbGUuY29t", "HTTP URL"},
		{"rO0ABXNyABFq", "Java serialized object"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, identifyPrefix(tc.input))
		})
	}
}

func TestFindBase64Matches(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"no match", "hello world", 0},
		{"single JSON", `token=eyJhbGciOiJIUzI1NiJ9`, 1},
		{"duplicate", `a=eyJhbGci&b=eyJhbGci`, 1},
		{"multiple types", `a=eyJhbGci&b=rO0ABXNy`, 2},
		{"with url encoding", `data=eyJ%61bGci`, 1},
		{"with padding", `data=eyJhbGciOiJIUzI1NiJ9==`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := findBase64Matches(tc.input)
			assert.Len(t, matches, tc.expected)
		})
	}
}
