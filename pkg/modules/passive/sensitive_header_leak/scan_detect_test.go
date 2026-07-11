package sensitive_header_leak

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// makeHTTPCtx builds a request/response pair with the given extra response
// header lines (each must end with \r\n).
func makeHTTPCtx(extraHeaders string) *httpmsg.HttpRequestResponse {
	return makeHTTPCtxStatus("200 OK", extraHeaders)
}

// makeHTTPCtxStatus builds a request/response pair with the given status line
// (e.g. "302 Found") and extra response header lines (each must end with \r\n).
func makeHTTPCtxStatus(statusLine, extraHeaders string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 " + statusLine + "\r\nContent-Type: text/html\r\n" + extraHeaders + "\r\n<html></html>"
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

// TestScanPerRequest_AWSKeyHeader drives a custom response header carrying an
// AWS access key ID and expects a public-identifier observation.
func TestScanPerRequest_AWSKeyHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Internal-Token: AKIAIOSFODNN7EXAMPLE\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Sensitive Data in Response Headers", results[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestScanPerRequest_HighEntropyInSuspiciousHeader drives a header whose name
// looks secret-bearing and whose value has high entropy, exercising the entropy
// path.
func TestScanPerRequest_HighEntropyInSuspiciousHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Api-Secret: aZ9kQ2mB7xV4nL1pR8sT3wY6cD0eF5gH\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
}

// TestScanPerRequest_AWSKeyHeaderIsPublicIdentifier ensures an access-key ID is
// not confused with the private AWS secret access key.
func TestScanPerRequest_AWSKeyHeaderIsPublicIdentifier(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Internal-Token: AKIAIOSFODNN7EXAMPLE\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestScanPerRequest_PrivateTokenFormatIsCandidate(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("X-Internal-Token: ghp_ABCDEF" + "GHIJKLMNOP" + "QRSTUVWXYZ" + "abcdefghij\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.NotContains(t, results[0].ExtractedResults[0], "ghp_ABCDEF" + "GHIJKLMNOP" + "QRSTUVWXYZ" + "abcdefghij")
}

// TestScanPerRequest_RedirectDowngraded mirrors the Cloudflare-Access finding: a
// JWT meta token in the Location header of a 302 redirect must be reported as
// Info/Tentative, not Medium/Firm — it is a login-flow navigation artifact.
func TestScanPerRequest_RedirectDowngraded(t *testing.T) {
	t.Parallel()
	m := New()
	loc := "Location: https://example.cloudflareaccess.com/cdn-cgi/access/login/example.com?meta=" +
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoibWV0YSIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\r\n"
	ctx := makeHTTPCtxStatus("302 Found", loc)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
	assert.Equal(t, severity.Tentative, results[0].Info.Confidence)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestScanPerRequest_AuthChallengeHeaderDowngraded covers a high-entropy
// Www-Authenticate challenge on a non-redirect status: a value confined to a
// redirect/auth-challenge header is downgraded regardless of status code.
func TestScanPerRequest_AuthChallengeHeaderDowngraded(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtxStatus("401 Unauthorized", "Www-Authenticate: Cloudflare-Access resource_metadata=\"aZ9kQ2mB7xV4nL1pR8sT3wY6cD0eF5gH\"\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
	assert.Equal(t, severity.Tentative, results[0].Info.Confidence)
}

// TestScanPerRequest_Benign drives a response with only common safe headers and
// expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("Cache-Control: no-cache\r\nX-Request-Id: 12345\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SetCookieOwnedByCookieModules(t *testing.T) {
	t.Parallel()
	m := New()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJyb2xlIjoiYWRtaW4ifQ.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	ctx := makeHTTPCtx("Set-Cookie: session=" + jwt + "; Path=/; HttpOnly; Secure\r\n")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_EdgeBlockSkipped verifies that a token-shaped value in the
// headers of a WAF/CDN edge block (a CloudFront 403) is not flagged: those
// headers are the edge's, not the application's.
func TestScanPerRequest_EdgeBlockSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), rawReq)
	rawResp := "HTTP/1.1 403 Forbidden\r\nServer: CloudFront\r\nX-Internal-Token: AKIAIOSFODNN7EXAMPLE\r\n\r\nThe request could not be satisfied."
	ctx := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
