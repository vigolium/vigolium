package jwt_claims_detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

var jwtBodyRegex = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

const maxTokensPerResponse = 5
const longLivedSeconds = 86400 // 24 hours

// Module implements the JWT Claim Analyzer passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JWT Claim Analyzer module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("passive_jwt_claims_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes JWTs in requests and responses for claim issues.
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

	// Collect JWT tokens from request and response
	tokens := m.findTokens(ctx)
	if len(tokens) == 0 {
		return nil, nil
	}

	var allIssues []string
	for _, token := range tokens {
		issues := analyzeToken(token)
		allIssues = append(allIssues, issues...)
	}

	if len(allIssues) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: allIssues,
			Info: output.Info{
				Name:        "JWT Claim Security Issues",
				Description: fmt.Sprintf("Found %d JWT claim issue(s)", len(allIssues)),
			},
		},
	}, nil
}

// findTokens extracts JWT tokens from request headers, cookies, and response body.
func (m *Module) findTokens(ctx *httpmsg.HttpRequestResponse) []string {
	seen := make(map[string]struct{})
	var tokens []string

	add := func(t string) {
		if _, ok := seen[t]; !ok && isJWT(t) {
			seen[t] = struct{}{}
			tokens = append(tokens, t)
		}
	}

	// Check request Authorization header
	if ctx.Request() != nil {
		auth := ctx.Request().Header("Authorization")
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			add(token)
		}

		// Check cookies
		cookies := ctx.Request().Header("Cookie")
		if cookies != "" {
			for cookie := range strings.SplitSeq(cookies, ";") {
				parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
				if len(parts) == 2 {
					add(parts[1])
				}
			}
		}
	}

	// Check response body
	if ctx.Response() != nil {
		body := ctx.Response().BodyToString()
		if body != "" {
			matches := jwtBodyRegex.FindAllString(body, maxTokensPerResponse)
			for _, match := range matches {
				add(match)
			}
		}
	}

	return tokens
}

// analyzeToken decodes a JWT and checks for claim issues.
func analyzeToken(token string) []string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil
	}

	redacted := redactJWT(token)
	var issues []string

	// Check alg:none
	if alg, ok := header["alg"]; ok {
		if algStr, ok := alg.(string); ok && strings.EqualFold(algStr, "none") {
			issues = append(issues, fmt.Sprintf("CRITICAL: alg=none (no signature verification) [%s]", redacted))
		}
	}

	// Check missing exp
	exp, hasExp := payload["exp"]
	if !hasExp {
		issues = append(issues, fmt.Sprintf("Missing 'exp' claim (token never expires) [%s]", redacted))
	}

	// Check long-lived token
	if hasExp {
		expFloat, expOk := toFloat64(exp)
		if expOk {
			now := float64(time.Now().Unix())
			iat, hasIat := payload["iat"]
			if hasIat {
				iatFloat, iatOk := toFloat64(iat)
				if iatOk && (expFloat-iatFloat) > longLivedSeconds {
					issues = append(issues, fmt.Sprintf("Long-lived token: exp-iat=%.0fs (>24h) [%s]", expFloat-iatFloat, redacted))
				}
			} else if (expFloat - now) > longLivedSeconds {
				issues = append(issues, fmt.Sprintf("Long-lived token: exp-now=%.0fs (>24h) [%s]", expFloat-now, redacted))
			}
		}
	}

	// Check privileged claims
	if admin, ok := payload["admin"]; ok {
		if b, ok := admin.(bool); ok && b {
			issues = append(issues, fmt.Sprintf("Privileged claim: admin=true [%s]", redacted))
		}
	}
	if isAdmin, ok := payload["is_admin"]; ok {
		if b, ok := isAdmin.(bool); ok && b {
			issues = append(issues, fmt.Sprintf("Privileged claim: is_admin=true [%s]", redacted))
		}
	}
	if role, ok := payload["role"]; ok {
		if roleStr, ok := role.(string); ok {
			lower := strings.ToLower(roleStr)
			if strings.Contains(lower, "admin") || strings.Contains(lower, "superuser") {
				issues = append(issues, fmt.Sprintf("Privileged claim: role=%s [%s]", roleStr, redacted))
			}
		}
	}

	// Check missing iss/aud
	if _, ok := payload["iss"]; !ok {
		issues = append(issues, fmt.Sprintf("Missing 'iss' claim [%s]", redacted))
	}
	if _, ok := payload["aud"]; !ok {
		issues = append(issues, fmt.Sprintf("Missing 'aud' claim [%s]", redacted))
	}

	return issues
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

// toFloat64 converts a JSON number (float64) from map[string]any.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
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
	return parts[0] + "." + payload + ".[sig]"
}
