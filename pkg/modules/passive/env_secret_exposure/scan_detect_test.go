package env_secret_exposure

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// makeHTTPCtx builds a request/response pair for the given path, response
// Content-Type, and body.
func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	return makeHTTPStatusCtx(path, contentType, body, 200, "OK")
}

func makeHTTPStatusCtx(path, contentType, body string, status int, reason string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\n\r\n%s", status, reason, contentType, body)
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

func TestCanProcess_TextResponse(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/app.js", "application/javascript", "console.log('hi')")
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_FrameworkSecret drives a NEXT_PUBLIC_* secret embedded in a
// JS bundle, exercising the framework env-var pattern path.
func TestScanPerRequest_FrameworkSecret(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const config = {NEXT_PUBLIC_API_SECRET: "s3cr3tValue12345"};`
	ctx := makeHTTPCtx("/_next/static/chunk.js", "application/javascript", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
	assert.Contains(t, results[0].Info.Name, "Public Environment Variable")
}

// TestScanPerRequest_DotenvFile drives a raw .env file served directly with a
// secret-bearing line, exercising the dotenv detection path.
func TestScanPerRequest_DotenvFile(t *testing.T) {
	t.Parallel()
	m := New()
	body := "DEBUG=true\nSTRIPE_KEY=sk_live_ab" + "cdef123456" + "7890\nPORT=3000\n"
	ctx := makeHTTPCtx("/.env", "text/plain", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, severity.High, results[0].Info.Severity)
	assert.Equal(t, "Credential-Shaped Value in Served Dotenv File", results[0].Info.Name)
}

func TestScanPerRequest_PublicBrowserIdentifiersAreNotSecrets(t *testing.T) {
	t.Parallel()
	tests := []string{
		`const x = {NEXT_PUBLIC_STRIPE_KEY: "pk_live_ab` + `cdefghijkl` + `mnopqrst"};`,
		`const x = {VITE_GOOGLE_API_KEY: "AIzaSyDUMMY_PUBLIC_BROWSER_KEY_123"};`,
		`const x = {REACT_APP_OAUTH_CREDENTIAL: "123456-abcdef.apps.googleusercontent.com"};`,
	}
	for _, body := range tests {
		m := New()
		results, err := m.ScanPerRequest(makeHTTPCtx("/assets/app.js", "application/javascript", body), &modkit.ScanContext{})
		require.NoError(t, err)
		assert.Empty(t, results, body)
	}
}

func TestScanPerRequest_GenericPublicValueIsNotEnough(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const config = {NEXT_PUBLIC_API_KEY: "browser-client-key"};`
	results, err := m.ScanPerRequest(makeHTTPCtx("/app.js", "application/javascript", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_DocumentationAssignmentIsIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<pre>NEXT_PUBLIC_API_SECRET: "ghp_abcdef` + `ghijklmnop` + `qrstuvwxyz` + `123456"</pre>`
	results, err := m.ScanPerRequest(makeHTTPCtx("/docs/environment", "text/html", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_DotenvSyntaxRequiresDotenvPath(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Configure the app with:\nPASSWORD=J7q9P2m4R8t6V3x1\n"
	results, err := m.ScanPerRequest(makeHTTPCtx("/examples/setup.txt", "text/plain", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_ErrorPageCannotEstablishExposure(t *testing.T) {
	t.Parallel()
	m := New()
	body := "STRIPE_KEY=sk_live_ab" + "cdef123456" + "7890\n"
	ctx := makeHTTPStatusCtx("/.env", "text/plain", body, 404, "Not Found")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_PlaceholderValueIsIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	body := "PASSWORD=your_password_here\n"
	results, err := m.ScanPerRequest(makeHTTPCtx("/.env.production", "text/plain", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a body without any secret indicators is
// not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>Welcome to the homepage</body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
