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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Find JWTs in request and response
	tokens := findLocatedJWTs(ctx)
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
	for _, located := range tokens {
		token := located.token
		weakSecret, alg := tryBruteForce(token, secrets)
		if weakSecret != "" {
			kind := output.RecordKindCandidate
			grade := output.EvidenceGradeCandidate
			description := fmt.Sprintf("JWT signature matches a known weak secret under %s, but the token was not observed in a strong server-issuance location; server trust and authorization impact remain unconfirmed.", alg)
			if located.strongServerIssue {
				kind = output.RecordKindFinding
				grade = output.EvidenceGradeImpact
				description = fmt.Sprintf("A JWT issued in a server-controlled response location has a signature that cryptographically matches a known weak secret under %s.", alg)
			}
			results = append(results, &output.ResultEvent{
				ModuleID:      ModuleID,
				RecordKind:    kind,
				EvidenceGrade: grade,
				Host:          urlx.Host,
				URL:           urlx.String(),
				Matched:       urlx.String(),
				Request:       rawRequest(ctx),
				Response:      rawResponse(ctx),
				ExtractedResults: []string{
					fmt.Sprintf("Algorithm: %s", alg),
					weakSecretEvidence(weakSecret),
					fmt.Sprintf("Observed locations: %s", strings.Join(located.sources, ", ")),
				},
				Info: output.Info{
					Name:        "JWT Signed with Weak Secret",
					Description: description,
					Severity:    severity.High,
					Confidence:  severity.Firm,
				},
				Metadata: map[string]any{
					"sources":                  located.sources,
					"strong_server_issuance":   located.strongServerIssue,
					"signature_verified":       true,
					"server_acceptance_tested": located.strongServerIssue,
					"authorization_tested":     false,
				},
			})
			continue
		}

		// Check for non-cryptographic (plaintext) signature
		declaredAlg := getJWTAlgorithm(token)
		if plaintext := getPlaintextSignature(token); plaintext != "" {
			kind := output.RecordKindCandidate
			grade := output.EvidenceGradeCandidate
			description := fmt.Sprintf("JWT declares %s but its signature decodes entirely to printable text. This is a strong candidate, but server trust was not established for the observed location.", declaredAlg)
			if located.strongServerIssue {
				kind = output.RecordKindFinding
				grade = output.EvidenceGradeImpact
				description = fmt.Sprintf("A JWT issued in a server-controlled response location declares %s but carries a printable, non-cryptographic signature.", declaredAlg)
			}
			results = append(results, &output.ResultEvent{
				ModuleID:      ModuleID,
				RecordKind:    kind,
				EvidenceGrade: grade,
				Host:          urlx.Host,
				URL:           urlx.String(),
				Matched:       urlx.String(),
				Request:       rawRequest(ctx),
				Response:      rawResponse(ctx),
				ExtractedResults: []string{
					fmt.Sprintf("Algorithm: %s", declaredAlg),
					fmt.Sprintf("Printable signature length: %d bytes (value redacted)", len(plaintext)),
					fmt.Sprintf("Observed locations: %s", strings.Join(located.sources, ", ")),
				},
				Info: output.Info{
					Name:        "JWT Has Non-Cryptographic Signature",
					Description: description,
					Severity:    severity.High,
					Confidence:  severity.Firm,
				},
				Metadata: map[string]any{
					"sources":                  located.sources,
					"strong_server_issuance":   located.strongServerIssue,
					"server_acceptance_tested": located.strongServerIssue,
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
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       rawRequest(ctx),
			Response:      rawResponse(ctx),
			ExtractedResults: []string{
				fmt.Sprintf("Algorithm: %s", asymmetricAlgSeen),
				"No weak HMAC secret found — algorithm confusion requires active verification",
			},
			Info: output.Info{
				Name:        "JWT Uses Asymmetric Algorithm — Potential Algorithm Confusion",
				Description: fmt.Sprintf("JWT declares %s. This is normal secure configuration; algorithm confusion is only possible if the server separately accepts an HMAC-forged variant, which was not tested.", asymmetricAlgSeen),
				Severity:    severity.Low,
				Confidence:  severity.Tentative,
			},
			Metadata: map[string]any{"algorithm_confusion_tested": false},
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

type locatedJWT struct {
	token             string
	sources           []string
	strongServerIssue bool
}

// findLocatedJWTs preserves where each token came from. A response
// Authorization or Set-Cookie value is strong evidence of server issuance;
// arbitrary response text and client-supplied request tokens are not.
func findLocatedJWTs(ctx *httpmsg.HttpRequestResponse) []locatedJWT {
	var tokens []locatedJWT
	index := make(map[string]int)
	add := func(token, source string, strongServerIssue bool) {
		token = strings.TrimSpace(token)
		if !isJWT(token) || jwtutil.IsPreAuthMetaTokenString(token) {
			return
		}
		if existing, ok := index[token]; ok {
			tokens[existing].sources = append(tokens[existing].sources, source)
			tokens[existing].strongServerIssue = tokens[existing].strongServerIssue || strongServerIssue
			return
		}
		index[token] = len(tokens)
		tokens = append(tokens, locatedJWT{token: token, sources: []string{source}, strongServerIssue: strongServerIssue})
	}

	if ctx.Request() != nil {
		if token := bearerToken(ctx.Request().Header("Authorization")); token != "" {
			add(token, "request Authorization", false)
		}
		if cookies := ctx.Request().Header("Cookie"); cookies != "" {
			for cookie := range strings.SplitSeq(cookies, ";") {
				parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
				if len(parts) == 2 {
					add(parts[1], "request Cookie", false)
				}
			}
		}
	}

	if ctx.Response() != nil && !modkit.IsEdgeBlockedResponse(ctx.Response()) {
		if token := bearerToken(ctx.Response().Header("Authorization")); token != "" {
			add(token, "response Authorization", true)
		}
		for _, cookie := range ctx.Response().Cookies() {
			add(cookie.Value, "response Set-Cookie", true)
		}
		body := ctx.Response().BodyToString()
		if len(body) > 0 && len(body) < 512*1024 {
			for _, match := range jwtBodyPattern.FindAllString(body, 10) {
				add(match, "response body", false)
			}
		}
	}

	return tokens
}

// findJWTs retains the original token-only helper used by callers and tests.
func findJWTs(ctx *httpmsg.HttpRequestResponse) []string {
	located := findLocatedJWTs(ctx)
	tokens := make([]string, 0, len(located))
	for _, item := range located {
		tokens = append(tokens, item.token)
	}
	return tokens
}

func bearerToken(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		return fields[1]
	}
	return ""
}

func weakSecretEvidence(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("Weak secret matched: length=%d, SHA-256 prefix=%x (value redacted)", len(secret), digest[:6])
}

func rawRequest(ctx *httpmsg.HttpRequestResponse) string {
	if ctx != nil && ctx.Request() != nil {
		return string(ctx.Request().Raw())
	}
	return ""
}

func rawResponse(ctx *httpmsg.HttpRequestResponse) string {
	if ctx != nil && ctx.Response() != nil {
		return string(ctx.Response().Raw())
	}
	return ""
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
