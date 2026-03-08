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
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
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

// ScanPerRequest checks JWTs in the request for weak HMAC secrets.
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

	// Find JWT in request
	token := findJWT(ctx)
	if token == "" {
		return nil, nil
	}

	// Load secrets lazily
	secrets, err := m.loadSecrets()
	if err != nil || len(secrets) == 0 {
		return nil, nil
	}

	// Try brute-force
	weakSecret, alg := tryBruteForce(token, secrets)
	if weakSecret == "" {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Algorithm: %s", alg),
				fmt.Sprintf("Weak secret: %s", redactSecret(weakSecret)),
				fmt.Sprintf("JWT: %s", redactJWT(token)),
			},
			Info: output.Info{
				Name:        "JWT Signed with Weak Secret",
				Description: fmt.Sprintf("JWT uses %s with a weak/known secret", alg),
			},
		},
	}, nil
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

	// Only test HMAC algorithms
	var newHash func() hash.Hash
	switch hdr.Alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
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

	// Try each secret
	for _, secret := range secrets {
		mac := hmac.New(newHash, secret)
		mac.Write(signingInput)
		expected := mac.Sum(nil)
		if hmac.Equal(expected, signature) {
			return string(secret), hdr.Alg
		}
	}

	return "", ""
}

// findJWT searches for a JWT token in Authorization headers and cookies.
func findJWT(ctx *httpmsg.HttpRequestResponse) string {
	if ctx.Request() == nil {
		return ""
	}

	// Check Authorization header
	auth := ctx.Request().Header("Authorization")
	if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
		if isJWT(token) {
			return token
		}
	}

	// Check cookies for JWT-like values
	cookies := ctx.Request().Header("Cookie")
	if cookies != "" {
		for cookie := range strings.SplitSeq(cookies, ";") {
			parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
			if len(parts) == 2 && isJWT(parts[1]) {
				return parts[1]
			}
		}
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

// redactSecret shows first 2 and last 2 characters, masking the rest.
func redactSecret(s string) string {
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// redactJWT shows the header and first 8 chars of payload, masking the rest.
func redactJWT(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return strings.Repeat("*", len(token))
	}
	payload := parts[1]
	if len(payload) > 8 {
		payload = payload[:8] + "..."
	}
	return parts[0] + "." + payload + ".[signature]"
}
