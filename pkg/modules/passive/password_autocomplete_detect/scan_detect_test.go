package password_autocomplete_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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

// TestScanPerRequest_PasswordNoAutocomplete records markup quality only.
func TestScanPerRequest_PasswordNoAutocomplete(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<form action="/login"><input type="password" name="pw"></form>`
	ctx := makeHTTPCtx("/login", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.NotEmpty(t, results[0].ExtractedResults)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// autocomplete=off is not treated as a security control and remains an
// informational semantic-markup observation.
func TestScanPerRequest_AutocompleteOffIsNotProtection(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<form action="/login"><input type="password" name="pw" autocomplete="off"></form>`
	ctx := makeHTTPCtx("/login", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "autocomplete=off")
}

func TestScanPerRequest_SemanticPasswordTokensAreAccepted(t *testing.T) {
	t.Parallel()
	body := `<form>` +
		`<input type="password" name="old" autocomplete="current-password webauthn">` +
		`<input type="password" name="new" autocomplete="new-password">` +
		`</form>`
	ctx := makeHTTPCtx("/account", "Content-Type: text/html\r\n", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NonAccountSecretsAreIgnored(t *testing.T) {
	t.Parallel()
	body := `<form>` +
		`<input type="password" name="otp_code" autocomplete="one-time-code">` +
		`<input type="password" name="cvv" autocomplete="cc-csc">` +
		`<input type="password" name="pin">` +
		`</form>`
	ctx := makeHTTPCtx("/checkout", "Content-Type: text/html\r\n", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_MarkupInsideScriptIsNotAnInput(t *testing.T) {
	t.Parallel()
	body := `<script>const example = '<input type="password" name="pw">';</script>`
	ctx := makeHTTPCtx("/docs", "Content-Type: text/html\r\n", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
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
