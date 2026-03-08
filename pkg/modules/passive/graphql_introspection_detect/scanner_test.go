package graphql_introspection_detect

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Medium, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeResponse, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func makeHTTPCtx(contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /graphql HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestIntrospectionDetected(t *testing.T) {
	m := New()
	body := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}`
	ctx := makeHTTPCtx("application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Info.Name, "GraphQL Introspection")
	assert.True(t, len(results[0].ExtractedResults) >= 2)
}

func TestNoMatchOnRegularJSON(t *testing.T) {
	m := New()
	body := `{"data":{"users":[{"id":1,"name":"Alice"}]}}`
	ctx := makeHTTPCtx("application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestPartialMatchNoPrimaryOnly(t *testing.T) {
	m := New()
	// Has __schema but no confirmation markers
	body := `{"data":{"__schema":{"description":"some schema"}}}`
	ctx := makeHTTPCtx("application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestSkipNonJSONContentType(t *testing.T) {
	m := New()
	body := `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`
	ctx := makeHTTPCtx("text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestNilResponse(t *testing.T) {
	m := New()
	rawReq := []byte("GET /graphql HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestTypeIntrospection(t *testing.T) {
	m := New()
	body := `{"data":{"__type":{"name":"User","fields":[]},"types":[{"name":"Query"}]}}`
	ctx := makeHTTPCtx("application/json; charset=utf-8", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
}
