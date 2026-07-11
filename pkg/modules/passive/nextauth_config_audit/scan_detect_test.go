package nextauth_config_audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// makeHTTPCtx builds an HTTPS request/response pair from the given response
// headers and body.
func makeHTTPCtx(headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/auth/session HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_InsecureCookie drives a NextAuth session cookie missing
// the Secure, HttpOnly, and SameSite attributes on an HTTPS response.
func TestScanPerRequest_InsecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: next-auth.session-token=abc123; Path=/\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "NextAuth.js Insecure Cookie")
	// Missing Secure + HttpOnly is a session-theft exposure → Medium.
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
	assert.Equal(t, output.RecordKindFinding, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeImpact, results[0].EvidenceGrade)
}

// TestScanPerRequest_SameSiteOnlyIsLow is the tiering regression: a cookie with
// Secure and HttpOnly set but no SameSite attribute is CSRF hygiene (browsers
// default to Lax), not a session-theft exposure, so it must be Low — not the old
// flat Medium.
func TestScanPerRequest_SameSiteOnlyIsLow(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: next-auth.session-token=abc123; Path=/; Secure; HttpOnly\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.Low, results[0].Info.Severity, "a missing-SameSite-only cookie is CSRF hygiene, not Medium")
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_SecureCookie verifies a fully hardened NextAuth cookie
// emits no finding.
func TestScanPerRequest_SecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: __Secure-next-auth.callback-url=https%3A%2F%2Fx; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonNextAuthCookie verifies an unrelated cookie is ignored.
func TestScanPerRequest_NonNextAuthCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: sessionid=xyz; Path=/\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_HelperCookieIsNotSessionCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: application/json\r\nSet-Cookie: next-auth.csrf-token=value12345; Path=/\r\n"
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "CSRF and callback helper cookies must not be labeled insecure session cookies")
}

func TestScanPerRequest_JWTClaimNameOnlyIsObservation(t *testing.T) {
	t.Parallel()
	m := New()
	token := testJWT(t, map[string]any{"sub": "user-1", "secret": nil})
	headers := fmt.Sprintf("Content-Type: application/json\r\nSet-Cookie: next-auth.session-token=%s; Path=/; Secure; HttpOnly; SameSite=Lax\r\n", token)
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
	assert.Equal(t, false, results[0].Metadata["substantive_values"])
}

func TestScanPerRequest_SubstantiveJWTClaimIsCandidate(t *testing.T) {
	t.Parallel()
	m := New()
	token := testJWT(t, map[string]any{"sub": "user-1", "access_token": "tok_live_7" + "Jr9mQ2vXp8" + "sK4nL"})
	headers := fmt.Sprintf("Content-Type: application/json\r\nSet-Cookie: next-auth.session-token=%s; Path=/; Secure; HttpOnly; SameSite=Lax\r\n", token)
	ctx := makeHTTPCtx(headers, `{}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, true, results[0].Metadata["substantive_values"])
	assert.NotContains(t, strings.Join(results[0].ExtractedResults, " "), "tok_live_7" + "Jr9mQ2vXp8" + "sK4nL")
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".signature"
}
