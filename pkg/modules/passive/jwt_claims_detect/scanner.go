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
	"github.com/vigolium/vigolium/pkg/modules/shared/jwtutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var jwtBodyRegex = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
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
	maxSev := severity.Undefined
	for _, token := range tokens {
		issues, sev := analyzeToken(token)
		allIssues = append(allIssues, issues...)
		if sev > maxSev {
			maxSev = sev
		}
	}

	if len(allIssues) == 0 {
		return nil, nil
	}

	// Severity tracks the WORST issue found rather than a flat module default.
	// alg=none is a strong candidate only after server acceptance is tested; the common observations —
	// a long exp, a missing iss/aud, or a privileged claim on an otherwise
	// well-signed token — are hygiene/best-practice observations, not exploitable
	// on their own. Reporting those at Medium over-severed one finding per
	// authenticated endpoint across every host; they belong at Low. Confidence is
	// Firm only for the dangerous alg=none case; hygiene leads stay Tentative.
	conf := severity.Tentative
	if maxSev >= severity.High {
		conf = severity.Firm
	}
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	description := fmt.Sprintf("Found %d JWT claim/configuration observation(s). Server-side validation, revocation, and authorization behavior were not tested.", len(allIssues))
	if maxSev >= severity.High {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		description = fmt.Sprintf("Found %d JWT issue(s), including an unsecured-algorithm candidate. The scanner did not submit a forged token, so server acceptance and authorization impact remain unconfirmed.", len(allIssues))
	}
	response := ""
	if ctx.Response() != nil {
		response = string(ctx.Response().Raw())
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         response,
			ExtractedResults: allIssues,
			Info: output.Info{
				Name:        "JWT Claim Security Issues",
				Description: description,
				Severity:    maxSev,
				Confidence:  conf,
			},
			Metadata: map[string]any{
				"token_count":              len(tokens),
				"forged_token_submitted":   false,
				"server_acceptance_tested": false,
				"authorization_tested":     false,
			},
		},
	}, nil
}

// findTokens extracts JWT tokens from request headers, cookies, and response body.
func (m *Module) findTokens(ctx *httpmsg.HttpRequestResponse) []string {
	seen := make(map[string]struct{})
	var tokens []string

	add := func(t string) {
		// Skip Cloudflare-Access-style pre-auth / metadata tokens (type=meta,
		// auth_status=NONE). They are framework SSO login-flow tokens embedded in
		// login URLs and reflected into the page body, not the application's own
		// JWTs, so claim-hygiene checks on them (e.g. "missing iss") are noise.
		if _, ok := seen[t]; !ok && isJWT(t) && !jwtutil.IsPreAuthMetaTokenString(t) {
			seen[t] = struct{}{}
			tokens = append(tokens, t)
		}
	}

	// Check request Authorization header
	if ctx.Request() != nil {
		auth := strings.TrimSpace(ctx.Request().Header("Authorization"))
		if fields := strings.Fields(auth); len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			add(fields[1])
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

	// Check response body. Skip WAF/CDN edge blocks: a JWT-shaped string on a
	// challenge/error page is the edge's, not the application's. Request-side
	// tokens above are kept — the client really sent them.
	if ctx.Response() != nil && !modkit.IsEdgeBlockedResponse(ctx.Response()) {
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

// analyzeToken decodes a JWT and checks for claim issues, returning the issues
// and the highest severity among them (severity.Undefined when there are none).
func analyzeToken(token string) ([]string, severity.Severity) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, severity.Undefined
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, severity.Undefined
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, severity.Undefined
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, severity.Undefined
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, severity.Undefined
	}

	var issues []string
	maxSev := severity.Undefined
	// add records an issue and raises the running max severity. Hygiene / best-
	// practice observations are Low; only alg=none (a forgeable token) is High.
	add := func(sev severity.Severity, format string, args ...any) {
		issues = append(issues, fmt.Sprintf(format, args...))
		if sev > maxSev {
			maxSev = sev
		}
	}

	// Check alg:none
	if alg, ok := header["alg"]; ok {
		if algStr, ok := alg.(string); ok && strings.EqualFold(algStr, "none") {
			add(severity.High, "Candidate: JWT header declares alg=none; server acceptance was not tested")
		}
	}

	// Check missing exp
	exp, hasExp := payload["exp"]
	if !hasExp {
		add(severity.Low, "Observation: Missing 'exp' claim; server-side lifetime and revocation were not assessed")
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
					add(severity.Low, "Observation: Long-lived token declaration, exp-iat=%.0fs (>24h)", expFloat-iatFloat)
				}
			} else if (expFloat - now) > longLivedSeconds {
				add(severity.Low, "Observation: Long-lived token declaration, more than 24h remains until exp (%.0fs)", expFloat-now)
			}
		}
	}

	// Check privileged claims
	if admin, ok := payload["admin"]; ok {
		if b, ok := admin.(bool); ok && b {
			add(severity.Low, "Observation: privileged claim admin=true; claim enforcement was not tested")
		}
	}
	if isAdmin, ok := payload["is_admin"]; ok {
		if b, ok := isAdmin.(bool); ok && b {
			add(severity.Low, "Observation: privileged claim is_admin=true; claim enforcement was not tested")
		}
	}
	if role, ok := payload["role"]; ok {
		if roleStr, ok := role.(string); ok {
			lower := strings.ToLower(roleStr)
			if strings.Contains(lower, "admin") || strings.Contains(lower, "superuser") {
				add(severity.Low, "Observation: privileged claim role=%s; claim enforcement was not tested", roleStr)
			}
		}
	}

	// Check missing iss/aud
	if _, ok := payload["iss"]; !ok {
		add(severity.Low, "Observation: missing 'iss' claim; single-issuer server policy may still be safe")
	}
	if _, ok := payload["aud"]; !ok {
		add(severity.Low, "Observation: missing 'aud' claim; audience enforcement was not tested")
	}

	return issues, maxSev
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
