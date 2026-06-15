package jwt_weak_secret

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jwtutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the JWT Weak Secret passive scanner.
type Module struct {
	modkit.BasePassiveModule
	secretsOnce sync.Once
	secrets     [][]byte
	secretsErr  error
	ds          dedup.Lazy[dedup.DiskSet]
}

// New creates a new JWT Weak Secret Detection module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeRequest,
		),
		ds: dedup.LazyDiskSet("passive_jwt_weak_secret"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// jwtHeader represents the minimal JWT header for algorithm extraction.
type jwtHeader struct {
	Alg string `json:"alg"`
}

// ScanPerRequest checks JWTs in the request and response for weak HMAC secrets.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup on host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Find JWTs in request and response
	tokens := findJWTs(ctx)
	if len(tokens) == 0 {
		return nil, nil
	}

	// Load secrets lazily
	secrets, err := m.loadSecrets()
	if err != nil || len(secrets) == 0 {
		return nil, nil
	}

	// Try brute-force on each token (findJWTs already deduplicates)
	var results []*output.ResultEvent
	var asymmetricAlgSeen string
	for _, token := range tokens {
		weakSecret, alg := tryBruteForce(token, secrets)
		if weakSecret != "" {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     urlx.Host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				Request:  string(ctx.Request().Raw()),
				ExtractedResults: []string{
					fmt.Sprintf("Algorithm: %s", alg),
					fmt.Sprintf("Weak secret: %s", weakSecret),
					fmt.Sprintf("JWT: %s", token),
				},
				Info: output.Info{
					Name:        "JWT Signed with Weak Secret",
					Description: fmt.Sprintf("JWT uses %s with a weak/known secret", alg),
				},
			})
			continue
		}

		// Check for non-cryptographic (plaintext) signature
		declaredAlg := getJWTAlgorithm(token)
		if plaintext := getPlaintextSignature(token); plaintext != "" {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     urlx.Host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				Request:  string(ctx.Request().Raw()),
				ExtractedResults: []string{
					fmt.Sprintf("Algorithm: %s", declaredAlg),
					fmt.Sprintf("Plaintext signature: %s", plaintext),
					fmt.Sprintf("JWT: %s", token),
				},
				Info: output.Info{
					Name:        "JWT Has Non-Cryptographic Signature",
					Description: fmt.Sprintf("JWT declares %s but the signature is plaintext ASCII, not a valid cryptographic output. The token can be trivially forged.", declaredAlg),
					Severity:    severity.High,
					Confidence:  severity.Firm,
				},
			})
			continue
		}

		// Track asymmetric tokens that weren't cracked
		if isAsymmetricAlg(declaredAlg) && asymmetricAlgSeen == "" {
			asymmetricAlgSeen = declaredAlg
		}
	}

	// Emit informational finding for uncracked asymmetric JWTs
	if asymmetricAlgSeen != "" && len(results) == 0 {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Algorithm: %s", asymmetricAlgSeen),
				"No weak HMAC secret found — algorithm confusion requires active verification",
			},
			Info: output.Info{
				Name:        "JWT Uses Asymmetric Algorithm — Potential Algorithm Confusion",
				Description: fmt.Sprintf("JWT declares %s. If the server also accepts HMAC-signed tokens, it may be vulnerable to algorithm confusion (CVE-2015-9235). Active testing is recommended.", asymmetricAlgSeen),
				Severity:    severity.Low,
				Confidence:  severity.Tentative,
			},
		})
	}

	return results, nil
}

// loadSecrets lazily loads the JWT secrets wordlist.
func (m *Module) loadSecrets() ([][]byte, error) {
	m.secretsOnce.Do(func() {
		data, err := wordlists.WordlistsFS.ReadFile("jwt.secrets.list")
		if err != nil {
			m.secretsErr = err
			return
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) > 0 {
				secret := make([]byte, len(line))
				copy(secret, line)
				m.secrets = append(m.secrets, secret)
			}
		}
		m.secretsErr = scanner.Err()
	})
	return m.secrets, m.secretsErr
}

// tryBruteForce attempts to find a weak HMAC secret for the given JWT.
// Returns the matched secret and algorithm, or empty strings if no match.
func tryBruteForce(token string, secrets [][]byte) (string, string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", ""
	}

	// Decode header to get algorithm
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ""
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return "", ""
	}

	// Build list of (hash function, label) pairs to try
	type hashVariant struct {
		newHash func() hash.Hash
		label   string
	}
	var variants []hashVariant

	switch hdr.Alg {
	case "HS256":
		variants = []hashVariant{{sha256.New, "HS256"}}
	case "HS384":
		variants = []hashVariant{{sha512.New384, "HS384"}}
	case "HS512":
		variants = []hashVariant{{sha512.New, "HS512"}}
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
		// Algorithm confusion: try all HMAC variants on asymmetric tokens (CVE-2015-9235).
		// Some servers may accept any HMAC variant, not just HS256.
		variants = []hashVariant{
			{sha256.New, fmt.Sprintf("%s (alg-confusion: tested as HS256)", hdr.Alg)},
			{sha512.New384, fmt.Sprintf("%s (alg-confusion: tested as HS384)", hdr.Alg)},
			{sha512.New, fmt.Sprintf("%s (alg-confusion: tested as HS512)", hdr.Alg)},
		}
	default:
		return "", ""
	}

	// Decode the existing signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ""
	}

	// The signing input is "header.payload"
	signingInput := []byte(parts[0] + "." + parts[1])

	// Try each variant and secret combination
	for _, v := range variants {
		for _, secret := range secrets {
			mac := hmac.New(v.newHash, secret)
			mac.Write(signingInput)
			expected := mac.Sum(nil)
			if hmac.Equal(expected, signature) {
				return string(secret), v.label
			}
		}
	}

	return "", ""
}

// getJWTAlgorithm extracts the "alg" field from a JWT header.
func getJWTAlgorithm(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return ""
	}
	return hdr.Alg
}

// getPlaintextSignature checks if a JWT signature decodes to printable ASCII text,
// which indicates it's not a real cryptographic output (HMAC/RSA/ECDSA signatures
// produce pseudo-random bytes). Returns the decoded plaintext, or empty string if
// the signature looks like valid cryptographic output.
func getPlaintextSignature(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) < 4 {
		return ""
	}

	// Check if all bytes are printable ASCII (space through tilde).
	// Real cryptographic signatures are pseudo-random and almost never all-printable.
	for _, b := range sig {
		if b < 0x20 || b > 0x7E {
			return ""
		}
	}

	return string(sig)
}

// isAsymmetricAlg returns true if the algorithm is an asymmetric signing algorithm.
func isAsymmetricAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
		return true
	}
	return false
}

// jwtBodyPattern matches JWT-like strings in response bodies.
// JWT headers always base64url-encode to "eyJ..." (from '{"'), so we require that prefix
// to avoid false positives on dotted identifiers like package names.
var jwtBodyPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// findJWTs searches for JWT tokens in request headers, cookies, response headers,
// response Set-Cookie, and response body.
func findJWTs(ctx *httpmsg.HttpRequestResponse) []string {
	var tokens []string
	seen := make(map[string]struct{})
	add := func(token string) {
		// Skip Cloudflare-Access-style pre-auth / metadata tokens (type=meta,
		// auth_status=NONE). These RS256 SSO login-flow tokens are reflected into
		// login pages and would otherwise emit a spurious "potential algorithm
		// confusion" finding — they are not the application's own JWTs.
		if jwtutil.IsPreAuthMetaTokenString(token) {
			return
		}
		if _, ok := seen[token]; !ok {
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}

	// --- Request ---
	if ctx.Request() != nil {
		// Check Authorization header
		auth := ctx.Request().Header("Authorization")
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			if isJWT(token) {
				add(token)
			}
		}

		// Check request cookies for JWT-like values
		cookies := ctx.Request().Header("Cookie")
		if cookies != "" {
			for cookie := range strings.SplitSeq(cookies, ";") {
				parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
				if len(parts) == 2 && isJWT(parts[1]) {
					add(parts[1])
				}
			}
		}
	}

	// --- Response ---
	// Skip WAF/CDN edge blocks: a JWT-shaped string on a challenge/error page is
	// the edge's, not the application's. Request-side tokens above are kept.
	if ctx.Response() != nil && !modkit.IsEdgeBlockedResponse(ctx.Response()) {
		// Check response Authorization header (some APIs echo tokens back)
		auth := ctx.Response().Header("Authorization")
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			if isJWT(token) {
				add(token)
			}
		}

		// Check response Set-Cookie headers for JWT-like values
		for _, cookie := range ctx.Response().Cookies() {
			if isJWT(cookie.Value) {
				add(cookie.Value)
			}
		}

		// Scan response body for JWT-like strings
		body := ctx.Response().BodyToString()
		if len(body) > 0 && len(body) < 512*1024 { // skip very large bodies
			for _, match := range jwtBodyPattern.FindAllString(body, 10) {
				if isJWT(match) {
					add(match)
				}
			}
		}
	}

	return tokens
}

// isJWT checks if a string looks like a JWT (3 base64url segments separated by dots).
func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if len(p) == 0 {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}
