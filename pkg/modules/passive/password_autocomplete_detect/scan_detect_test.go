package password_autocomplete_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair from the given path, response
// headers, and HTML body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body
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

// TestScanPerRequest_PasswordNoAutocomplete drives a password input without
// autocomplete disabled, the vulnerable case.
func TestScanPerRequest_PasswordNoAutocomplete(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<form action="/login"><input type="password" name="pw"></form>`
	ctx := makeHTTPCtx("/login", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.NotEmpty(t, results[0].ExtractedResults)
}

// TestScanPerRequest_AutocompleteOff verifies a password field with
// autocomplete="off" is not flagged.
func TestScanPerRequest_AutocompleteOff(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<form action="/login"><input type="password" name="pw" autocomplete="off"></form>`
	ctx := makeHTTPCtx("/login", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoPasswordField verifies a page without a password input
// produces no finding.
func TestScanPerRequest_NoPasswordField(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<form action="/search"><input type="text" name="q"></form>`
	ctx := makeHTTPCtx("/search", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
