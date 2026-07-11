package jwt_weak_secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// signHS256 creates a JWT signed with HS256 using the given header JSON and secret.
func signHS256(headerJSON, payload string, secret []byte) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := h + "." + p
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// makeHTTPCtx builds a test HttpRequestResponse from raw request/response strings.
func makeHTTPCtx(rawReq, rawResp string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

const defaultReq = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
const defaultResp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"

func makeHTTPCtxWithAuth(token string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n\r\n", token)
	return makeHTTPCtx(rawReq, defaultResp)
}

func makeHTTPCtxWithResponseHeader(headerName, headerValue string) *httpmsg.HttpRequestResponse {
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%s: %s\r\n\r\n{}", headerName, headerValue)
	return makeHTTPCtx(defaultReq, rawResp)
}

func makeHTTPCtxWithResponseBody(body string) *httpmsg.HttpRequestResponse {
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n%s", body)
	return makeHTTPCtx(defaultReq, rawResp)
}

func makeHTTPCtxWithSetCookie(cookieName, cookieValue string) *httpmsg.HttpRequestResponse {
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: %s=%s; Path=/\r\n\r\n{}", cookieName, cookieValue)
	return makeHTTPCtx(defaultReq, rawResp)
}

// --- tryBruteForce unit tests ---

func TestTryBruteForce_HS256WeakSecret(t *testing.T) {
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, secret)

	matched, alg := tryBruteForce(token, [][]byte{[]byte("wrong"), secret})
	assert.Equal(t, "secret", matched)
	assert.Equal(t, "HS256", alg)
}

func TestTryBruteForce_HS256NoMatch(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, []byte("very-strong-secret-not-in-list"))

	matched, alg := tryBruteForce(token, [][]byte{[]byte("secret"), []byte("password")})
	assert.Empty(t, matched)
	assert.Empty(t, alg)
}

func TestTryBruteForce_RS256AlgConfusion(t *testing.T) {
	// Token header claims RS256 but is actually signed with HS256 using a weak secret.
	// This simulates the algorithm confusion attack (CVE-2015-9235).
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"RS256"}`, `{"sub":"1234567890"}`, secret)

	matched, alg := tryBruteForce(token, [][]byte{[]byte("wrong"), secret})
	assert.Equal(t, "secret", matched)
	assert.Contains(t, alg, "RS256")
	assert.Contains(t, alg, "alg-confusion")
	assert.Contains(t, alg, "HS256")
}

func TestTryBruteForce_ES256AlgConfusion(t *testing.T) {
	secret := []byte("password")
	token := signHS256(`{"typ":"JWT","alg":"ES256"}`, `{"sub":"test"}`, secret)

	matched, alg := tryBruteForce(token, [][]byte{secret})
	assert.Equal(t, "password", matched)
	assert.Contains(t, alg, "ES256 (alg-confusion: tested as HS256)")
}

func TestTryBruteForce_UnknownAlg(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"CUSTOM"}`, `{"sub":"1234567890"}`, []byte("secret"))

	matched, alg := tryBruteForce(token, [][]byte{[]byte("secret")})
	assert.Empty(t, matched)
	assert.Empty(t, alg)
}

func TestTryBruteForce_InvalidToken(t *testing.T) {
	matched, alg := tryBruteForce("not-a-jwt", [][]byte{[]byte("secret")})
	assert.Empty(t, matched)
	assert.Empty(t, alg)
}

// --- findJWTs unit tests ---

func TestFindJWTs_RequestAuthHeader(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("key"))
	ctx := makeHTTPCtxWithAuth(token)
	tokens := findJWTs(ctx)
	require.Len(t, tokens, 1)
	assert.Equal(t, token, tokens[0])
}

func TestFindJWTs_ResponseAuthHeader(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("key"))
	ctx := makeHTTPCtxWithResponseHeader("Authorization", "Bearer "+token)
	tokens := findJWTs(ctx)
	require.Len(t, tokens, 1)
	assert.Equal(t, token, tokens[0])
}

func TestFindJWTs_ResponseSetCookie(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("key"))
	ctx := makeHTTPCtxWithSetCookie("session", token)
	tokens := findJWTs(ctx)
	require.Len(t, tokens, 1)
	assert.Equal(t, token, tokens[0])
}

func TestFindJWTs_ResponseBody(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("key"))
	body := fmt.Sprintf(`{"access_token":"%s"}`, token)
	ctx := makeHTTPCtxWithResponseBody(body)
	tokens := findJWTs(ctx)
	require.Len(t, tokens, 1)
	assert.Equal(t, token, tokens[0])
}

func TestFindJWTs_ResponseBodyNoJWT(t *testing.T) {
	ctx := makeHTTPCtxWithResponseBody(`{"message":"hello world"}`)
	tokens := findJWTs(ctx)
	assert.Empty(t, tokens)
}

func TestFindJWTs_DeduplicatesAcrossLocations(t *testing.T) {
	// Same JWT in request auth header AND response body — findJWTs should dedup
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("secret"))
	rawReq := fmt.Sprintf("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n\r\n", token)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"%s\"}", token)
	ctx := makeHTTPCtx(rawReq, rawResp)

	// findJWTs should return exactly one token despite appearing in two locations
	tokens := findJWTs(ctx)
	require.Len(t, tokens, 1)
	assert.Equal(t, token, tokens[0])

	// ScanPerRequest should also produce only one finding
	m := New()
	scanCtx := &modkit.ScanContext{}
	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// --- ScanPerRequest integration tests ---

func TestScanPerRequest_RS256AlgConfusion(t *testing.T) {
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"RS256"}`, `{"sub":"1234567890"}`, secret)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "RS256")
	assert.Contains(t, results[0].ExtractedResults[0], "alg-confusion")
	assert.Contains(t, results[0].Info.Description, "RS256")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
}

func TestScanPerRequest_HS256WeakSecret(t *testing.T) {
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, secret)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "HS256")
	assert.NotContains(t, results[0].ExtractedResults[0], "alg-confusion")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	for _, evidence := range results[0].ExtractedResults {
		assert.NotContains(t, evidence, token)
		assert.NotEqual(t, "Weak secret: secret", evidence)
	}
}

func TestScanPerRequest_JWTInResponseBody(t *testing.T) {
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, secret)
	body := fmt.Sprintf(`{"access_token":"%s"}`, token)
	ctx := makeHTTPCtxWithResponseBody(body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "HS256")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
}

func TestScanPerRequest_JWTInResponseSetCookie(t *testing.T) {
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, secret)
	ctx := makeHTTPCtxWithSetCookie("token", token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults[0], "HS256")
	assert.Equal(t, output.RecordKindFinding, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeImpact, results[0].EvidenceGrade)
}

func TestScanPerRequest_NoJWT(t *testing.T) {
	m := New()
	ctx := makeHTTPCtxWithResponseBody(`{"message":"no tokens here"}`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

// makeRSAMetaToken builds an RS256 token with a Cloudflare-Access pre-auth meta
// payload and a non-HMAC signature, so it can't be brute-forced and would
// otherwise emit the asymmetric "algorithm confusion" informational finding.
func makeRSAMetaToken(payload string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"RS256"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := h + "." + p
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(key.N.Bytes())
}

func TestFindJWTs_SkipsCloudflareAccessMetaToken(t *testing.T) {
	// type=meta and auth_status=NONE are the Cloudflare Access pre-auth shape.
	for _, payload := range []string{
		`{"type":"meta","aud":"app","exp":1781357251}`,
		`{"auth_status":"NONE","aud":"app","exp":1781357251}`,
	} {
		token := makeRSAMetaToken(payload)
		ctx := makeHTTPCtxWithResponseBody(fmt.Sprintf(`{"meta":"%s"}`, token))
		assert.Empty(t, findJWTs(ctx), "pre-auth meta token must be skipped: %s", payload)
	}
}

func TestScanPerRequest_SkipsCloudflareAccessMetaToken(t *testing.T) {
	m := New()
	token := makeRSAMetaToken(`{"type":"meta","auth_status":"NONE","aud":"app","exp":1781357251}`)
	// Reflected into the login-page body, exactly as on a Cloudflare Access SSO page.
	ctx := makeHTTPCtxWithResponseBody(fmt.Sprintf(`<form action="/cdn-cgi/access/login?meta=%s">`, token))
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results, "pre-auth meta token must not produce an algorithm-confusion finding")
}

func TestScanPerRequest_AsymmetricNonMetaTokenStillFlagged(t *testing.T) {
	// A normal asymmetric application token (real identity, no meta marker) must
	// still produce the informational algorithm-confusion finding — the skip is
	// scoped to pre-auth meta tokens only.
	m := New()
	token := makeRSAMetaToken(`{"sub":"1234567890","role":"user"}`)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Info.Name, "Algorithm Confusion")
}

// signHMAC creates a JWT signed with an arbitrary HMAC hash function.
func signHMAC(headerJSON, payload string, secret []byte, newHash func() hash.Hash) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := h + "." + p
	mac := hmac.New(newHash, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// makeRSASignedJWT creates a JWT with a real RSA signature (not HMAC).
// This simulates a genuinely asymmetric-signed token that won't match any HMAC secret.
func makeRSASignedJWT(alg string) string {
	headerJSON := fmt.Sprintf(`{"typ":"JWT","alg":"%s"}`, alg)
	payload := `{"sub":"1234567890","role":"admin"}`
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := h + "." + p

	// Generate a real RSA signature
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	// Use the RSA modulus bytes as a fake signature — it's a valid-looking
	// byte sequence that will never match any HMAC computation.
	sig := key.N.Bytes()
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// makePlaintextSigJWT creates a JWT with a plaintext ASCII signature (not cryptographic).
func makePlaintextSigJWT(headerJSON, payload, plaintextSig string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte(plaintextSig))
	return h + "." + p + "." + sig
}

// --- Plaintext signature tests ---

func TestGetPlaintextSignature_Plaintext(t *testing.T) {
	token := makePlaintextSigJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"1"}`,
		"signature_generated_with_secret123",
	)
	assert.Equal(t, "signature_generated_with_secret123", getPlaintextSignature(token))
}

func TestGetPlaintextSignature_CryptoSig(t *testing.T) {
	// A real HMAC signature should NOT be detected as plaintext
	token := signHS256(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"1"}`, []byte("secret"))
	assert.Empty(t, getPlaintextSignature(token))
}

func TestGetPlaintextSignature_Short(t *testing.T) {
	// Signatures shorter than 4 bytes are ignored
	token := makePlaintextSigJWT(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"1"}`, "abc")
	assert.Empty(t, getPlaintextSignature(token))
}

func TestScanPerRequest_PlaintextSignature(t *testing.T) {
	m := New()
	// This is the exact pattern from the user's Juice Shop request
	token := makePlaintextSigJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"id":1,"username":"admin","role":"admin","iat":1773076325,"exp":1773079925}`,
		"signature_generated_with_secret123",
	)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, severity.High, results[0].Info.Severity)
	assert.Equal(t, severity.Firm, results[0].Info.Confidence)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Contains(t, results[0].Info.Name, "Non-Cryptographic Signature")
	assert.Contains(t, results[0].Info.Description, "printable text")
	assert.Contains(t, results[0].ExtractedResults[0], "HS256")
	assert.Contains(t, results[0].ExtractedResults[1], "Printable signature length")
	assert.NotContains(t, results[0].ExtractedResults[1], "signature_generated_with_secret123")
}

func TestScanPerRequest_PlaintextSignature_NotEmittedWhenSecretFound(t *testing.T) {
	// If brute-force finds the weak secret, emit the confirmed finding, not plaintext
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"1"}`, secret)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Info.Name, "Weak Secret")
}

// --- Informational finding tests ---

func TestScanPerRequest_AsymmetricJWT_InformationalFinding(t *testing.T) {
	m := New()
	token := makeRSASignedJWT("RS256")
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Should be low severity, tentative confidence
	assert.Equal(t, severity.Low, results[0].Info.Severity)
	assert.Equal(t, severity.Tentative, results[0].Info.Confidence)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
	assert.Contains(t, results[0].Info.Name, "Algorithm Confusion")
	assert.Contains(t, results[0].Info.Description, "RS256")
	assert.Contains(t, results[0].Info.Description, "not tested")
	assert.Contains(t, results[0].ExtractedResults[0], "RS256")
}

func TestScanPerRequest_AsymmetricJWT_ES256(t *testing.T) {
	m := New()
	token := makeRSASignedJWT("ES256")
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Info.Description, "ES256")
}

func TestScanPerRequest_AsymmetricJWT_NoInfoWhenSecretFound(t *testing.T) {
	// If a weak secret IS found (alg confusion match), confirmed finding takes precedence —
	// no informational finding should be emitted.
	m := New()
	secret := []byte("secret")
	token := signHS256(`{"typ":"JWT","alg":"RS256"}`, `{"sub":"1234567890"}`, secret)
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	// Should be the confirmed finding, not the informational one
	assert.Contains(t, results[0].Info.Name, "Weak Secret")
	assert.NotEqual(t, severity.Low, results[0].Info.Severity)
}

func TestScanPerRequest_HS256JWT_NoInformationalFinding(t *testing.T) {
	// HS256 JWT with no match should NOT produce an informational finding
	m := New()
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("ultra-strong-secret-xyz-9999"))
	ctx := makeHTTPCtxWithAuth(token)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

// --- Multi-algorithm brute-force tests ---

func TestTryBruteForce_RS256AlgConfusion_HS384(t *testing.T) {
	// Token header claims RS256 but is signed with HS384
	secret := []byte("secret")
	token := signHMAC(`{"typ":"JWT","alg":"RS256"}`, `{"sub":"1"}`, secret, sha512.New384)

	matched, alg := tryBruteForce(token, [][]byte{secret})
	assert.Equal(t, "secret", matched)
	assert.Contains(t, alg, "RS256")
	assert.Contains(t, alg, "HS384")
}

func TestTryBruteForce_RS256AlgConfusion_HS512(t *testing.T) {
	// Token header claims RS256 but is signed with HS512
	secret := []byte("password")
	token := signHMAC(`{"typ":"JWT","alg":"RS256"}`, `{"sub":"1"}`, secret, sha512.New)

	matched, alg := tryBruteForce(token, [][]byte{secret})
	assert.Equal(t, "password", matched)
	assert.Contains(t, alg, "RS256")
	assert.Contains(t, alg, "HS512")
}

// --- Helper function tests ---

func TestGetJWTAlgorithm(t *testing.T) {
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1"}`, []byte("key"))
	assert.Equal(t, "HS256", getJWTAlgorithm(token))

	rsaToken := makeRSASignedJWT("RS256")
	assert.Equal(t, "RS256", getJWTAlgorithm(rsaToken))

	assert.Equal(t, "", getJWTAlgorithm("not-a-jwt"))
}

func TestIsAsymmetricAlg(t *testing.T) {
	for _, alg := range []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"} {
		assert.True(t, isAsymmetricAlg(alg), alg)
	}
	for _, alg := range []string{"HS256", "HS384", "HS512", "none", ""} {
		assert.False(t, isAsymmetricAlg(alg), alg)
	}
}
