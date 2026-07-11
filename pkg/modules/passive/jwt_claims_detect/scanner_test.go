package jwt_claims_detect

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Medium, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeBoth, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

// buildJWT creates a JWT from JSON header and payload strings with a dummy signature.
func buildJWT(headerJSON, payloadJSON string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + ".dummysignature"
}

func makeHTTPCtxWithAuth(token string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n\r\n", token)
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func makeHTTPCtxWithBody(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestAlgNone(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"none"}`, `{"sub":"1","iss":"test","aud":"app","exp":9999999999}`)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "alg=none")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	for _, issue := range results[0].ExtractedResults {
		assert.NotContains(t, issue, token)
	}
}

func TestMissingExp(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"HS256"}`, `{"sub":"1","iss":"test","aud":"app"}`)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	found := false
	for _, r := range results[0].ExtractedResults {
		if assert.ObjectsAreEqual("", "") || true {
			if len(r) > 0 && r[0:1] == "M" {
				found = true
			}
		}
	}
	_ = found
	// Just verify there are issues about missing exp
	hasExpIssue := false
	for _, r := range results[0].ExtractedResults {
		if contains(r, "Missing 'exp'") {
			hasExpIssue = true
		}
	}
	assert.True(t, hasExpIssue, "should detect missing exp claim")
}

func TestLongLivedToken(t *testing.T) {
	m := New()
	now := time.Now().Unix()
	iat := now
	exp := now + 7*86400 // 7 days
	payload := fmt.Sprintf(`{"sub":"1","iss":"test","aud":"app","iat":%d,"exp":%d}`, iat, exp)
	token := buildJWT(`{"alg":"HS256"}`, payload)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	hasLongLived := false
	for _, r := range results[0].ExtractedResults {
		if contains(r, "Long-lived") {
			hasLongLived = true
		}
	}
	assert.True(t, hasLongLived, "should detect long-lived token")
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestPrivilegedClaims(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"HS256"}`, `{"sub":"1","iss":"test","aud":"app","exp":9999999999,"admin":true,"role":"superuser"}`)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	hasAdmin := false
	hasRole := false
	for _, r := range results[0].ExtractedResults {
		if contains(r, "admin=true") {
			hasAdmin = true
		}
		if contains(r, "role=superuser") {
			hasRole = true
		}
	}
	assert.True(t, hasAdmin, "should detect admin=true")
	assert.True(t, hasRole, "should detect role=superuser")
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestLongLivedTokenIsLow is the regression for the severity-inflation false
// positive: a well-signed token whose only issue is a long expiry (or a missing
// iss/aud) is a hygiene lead, not a Medium vulnerability. It must be reported at
// Low/Tentative, not the flat module-default Medium.
func TestLongLivedTokenIsLow(t *testing.T) {
	m := New()
	now := time.Now().Unix()
	// exp 60 days out, missing iss/aud — the exact shape of the reported findings.
	payload := fmt.Sprintf(`{"sub":"1","iat":%d,"exp":%d}`, now, now+60*86400)
	token := buildJWT(`{"alg":"HS256"}`, payload)
	ctx := makeHTTPCtxWithAuth(token)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.Low, results[0].Info.Severity, "hygiene-only JWT issues must be Low, not Medium")
	assert.Equal(t, severity.Tentative, results[0].Info.Confidence)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestAlgNoneIsHighCandidate verifies alg=none is prioritized above hygiene but
// remains a candidate until a forged token is accepted by the server.
func TestAlgNoneIsHigh(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"none"}`, `{"sub":"1","iss":"test","aud":"app","exp":9999999999}`)
	ctx := makeHTTPCtxWithAuth(token)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.High, results[0].Info.Severity, "alg=none is a forgeable-token issue and must outrank hygiene leads")
	assert.Equal(t, severity.Firm, results[0].Info.Confidence)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, false, results[0].Metadata["server_acceptance_tested"])
}

func TestHealthyJWT(t *testing.T) {
	m := New()
	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"1","iss":"test","aud":"app","iat":%d,"exp":%d}`, now, now+3600)
	token := buildJWT(`{"alg":"HS256"}`, payload)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestJWTInResponseBody(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"none"}`, `{"sub":"1","iss":"test","aud":"app","exp":9999999999}`)
	body := fmt.Sprintf(`{"access_token":"%s"}`, token)
	ctx := makeHTTPCtxWithBody(body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "alg=none")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
}

func TestLowercaseBearerSchemeIsAccepted(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"HS256"}`, `{"sub":"1"}`)
	rawReq := fmt.Sprintf("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: bearer %s\r\n\r\n", token)
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), []byte(rawReq))
	ctx := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestSkipsCloudflareAccessMetaToken_InBody(t *testing.T) {
	m := New()
	// A Cloudflare Access pre-auth meta token (type=meta) has no iss; without the
	// skip the module would emit a "Missing 'iss' claim" issue. The token is
	// reflected into the login-page body, exactly as on the real SSO page.
	token := buildJWT(`{"alg":"RS256","typ":"JWT"}`, `{"type":"meta","aud":"app","exp":9999999999}`)
	body := fmt.Sprintf(`<form action="/cdn-cgi/access/login?meta=%s">`, token)
	ctx := makeHTTPCtxWithBody(body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results, "pre-auth meta token must not produce claim issues")
}

func TestSkipsCloudflareAccessMetaToken_AuthStatusNone(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"RS256","typ":"JWT"}`, `{"auth_status":"NONE","aud":"app","exp":9999999999}`)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results, "auth_status=NONE pre-auth token must not produce claim issues")
}

func TestNilResponse(t *testing.T) {
	m := New()
	token := buildJWT(`{"alg":"HS256"}`, `{"sub":"1","iss":"test","aud":"app","exp":9999999999}`)
	rawReq := fmt.Sprintf("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n\r\n", token)
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	scanCtx := &modkit.ScanContext{}

	// Should still work — PassiveScanScopeBoth but response is nil
	// BasePassiveModule.CanProcess will return false, so executor won't call us.
	// But if called directly, we should handle gracefully.
	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	// May or may not find issues from request-only JWT
	_ = results
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
