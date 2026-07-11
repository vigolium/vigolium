package nextauth_config_audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	// NextAuth cookie name patterns.
	nextAuthCookieNames = []string{
		"next-auth.session-token",
		"__secure-next-auth.session-token",
		"next-auth.csrf-token",
		"next-auth.callback-url",
		"__secure-next-auth.callback-url",
		"__host-next-auth.csrf-token",
	}

	// JWT claims that indicate sensitive data exposure.
	sensitiveClaims = []string{
		"password", "passwd", "secret", "api_key", "apikey",
		"access_token", "refresh_token", "private_key", "privatekey",
		"credit_card", "ssn", "database_url", "db_password",
	}
)

// Module implements the NextAuth.js config audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new NextAuth.js Configuration Audit module.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("nextauth_config_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest inspects responses for NextAuth.js configuration issues.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by host
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Collect Set-Cookie headers
	var setCookies []string
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			setCookies = append(setCookies, h.Value)
		}
	}

	if len(setCookies) == 0 {
		return nil, nil
	}

	isHTTPS := strings.EqualFold(urlx.Scheme, "https")
	var results []*output.ResultEvent

	for _, cookie := range setCookies {
		parsedCookie, parseErr := nethttp.ParseSetCookie(cookie)
		if parseErr != nil || parsedCookie == nil {
			continue
		}
		cookieLower := strings.ToLower(parsedCookie.Name)

		// Check if this is a NextAuth cookie
		var matchedName string
		for _, name := range nextAuthCookieNames {
			if cookieLower == name {
				matchedName = name
				break
			}
		}
		if matchedName == "" {
			continue
		}

		// Only the session token is an authentication cookie. NextAuth callback and
		// CSRF helper cookies have different browser-access semantics and must not be
		// called session-theft flaws merely because HttpOnly is absent.
		isSessionCookie := strings.Contains(matchedName, "session-token")

		// Check cookie security flags. Severity tracks the WORST issue rather than a
		// flat Medium: a missing Secure/HttpOnly flag on a session cookie is a real
		// session-theft exposure (Medium), but a missing SameSite attribute (browsers
		// default to Lax) or SameSite=None-without-Secure (the browser rejects the
		// cookie) is CSRF hygiene (Low). Reporting a SameSite-only cookie at Medium
		// over-severed it.
		var issues []string
		sev := severity.Low

		if isSessionCookie && isHTTPS && !parsedCookie.Secure {
			issues = append(issues, "Missing Secure flag on HTTPS")
			sev = severity.Medium
		}

		if isSessionCookie && !parsedCookie.HttpOnly {
			issues = append(issues, "Missing HttpOnly flag")
			sev = severity.Medium
		}

		if isSessionCookie && (parsedCookie.SameSite == 0 || parsedCookie.SameSite == nethttp.SameSiteDefaultMode) {
			issues = append(issues, "Missing SameSite attribute")
		} else if isSessionCookie && parsedCookie.SameSite == nethttp.SameSiteNoneMode && !parsedCookie.Secure {
			issues = append(issues, "SameSite=None without Secure flag")
		}

		if len(issues) > 0 {
			kind := output.RecordKindObservation
			grade := output.EvidenceGradeObservation
			if sev >= severity.Medium {
				kind = output.RecordKindFinding
				grade = output.EvidenceGradeImpact
			}
			results = append(results, &output.ResultEvent{
				ModuleID:      ModuleID,
				RecordKind:    kind,
				EvidenceGrade: grade,
				Host:          urlx.Host,
				URL:           urlx.String(),
				Matched:       urlx.String(),
				Request:       string(ctx.Request().Raw()),
				Response:      string(ctx.Response().Raw()),
				ExtractedResults: []string{
					fmt.Sprintf("Cookie: %s", matchedName),
					fmt.Sprintf("Issues: %s", strings.Join(issues, "; ")),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("NextAuth.js Insecure Cookie: %s", matchedName),
					Description: fmt.Sprintf("NextAuth session cookie %q has insecure configuration: %s", matchedName, strings.Join(issues, "; ")),
					Severity:    sev,
					Confidence:  severity.Firm,
					Tags:        []string{"nextauth", "cookies", "session-management"},
					Reference:   []string{"https://next-auth.js.org/configuration/options#cookies"},
				},
				Metadata: map[string]any{
					"cookie_name":    matchedName,
					"issues":         issues,
					"session_cookie": isSessionCookie,
				},
			})
		}

		// For session tokens, attempt JWT decode to check for sensitive claims.
		// Pass the parsed value so cookie attributes cannot be mistaken for token data.
		if isSessionCookie {
			if sensitiveResults := m.checkJWTClaims(
				parsedCookie.Value,
				matchedName,
				urlx.Host,
				urlx.String(),
				string(ctx.Request().Raw()),
				string(ctx.Response().Raw()),
			); len(sensitiveResults) > 0 {
				results = append(results, sensitiveResults...)
			}
		}
	}

	return results, nil
}

// checkJWTClaims decodes a JWS-shaped session token and distinguishes a claim
// name observation from a substantive-value candidate. A key called "secret"
// with a null, redacted, or example value is useful hunting context, but is not
// evidence that secret material was exposed.
func (m *Module) checkJWTClaims(tokenValue, cookieName, host, url, request, response string) []*output.ResultEvent {
	// JWT format: header.payload.signature
	jwtParts := strings.Split(tokenValue, ".")
	if len(jwtParts) != 3 {
		return nil
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	var foundSensitive []string
	var substantiveClaims []string
	for key, value := range claims {
		keyLower := strings.ToLower(key)
		for _, sensitive := range sensitiveClaims {
			if strings.Contains(keyLower, sensitive) {
				foundSensitive = append(foundSensitive, key)
				if isSubstantiveClaimValue(value, 0) {
					substantiveClaims = append(substantiveClaims, key)
				}
				break
			}
		}
	}

	if len(foundSensitive) == 0 {
		return nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Low
	name := "NextAuth.js JWT Sensitive Claim Names"
	description := fmt.Sprintf(
		"Decoded a JWS-shaped NextAuth session token containing security-relevant claim names (%s), but their values were empty, redacted, placeholders, or otherwise non-substantive. This is retained as an observation only.",
		strings.Join(foundSensitive, ", "),
	)
	if len(substantiveClaims) > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.High
		name = "NextAuth.js JWT Potential Sensitive Data Exposure"
		description = fmt.Sprintf(
			"A decoded JWS-shaped NextAuth session token contains substantive values under security-relevant claims (%s). The values were not emitted. Credential validity, ownership, and downstream privilege were not tested, so this is a candidate rather than confirmed misuse.",
			strings.Join(substantiveClaims, ", "),
		)
	}

	return []*output.ResultEvent{
		{
			ModuleID:      ModuleID,
			RecordKind:    kind,
			EvidenceGrade: grade,
			Host:          host,
			URL:           url,
			Matched:       url,
			Request:       request,
			Response:      response,
			ExtractedResults: []string{
				fmt.Sprintf("Cookie: %s", cookieName),
				fmt.Sprintf("Security-relevant JWT claim names: %s", strings.Join(foundSensitive, ", ")),
				fmt.Sprintf("Claims with substantive values: %s", strings.Join(substantiveClaims, ", ")),
			},
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    sev,
				Confidence:  severity.Firm,
				Tags:        []string{"nextauth", "jwt", "information-disclosure"},
				Reference:   []string{"https://next-auth.js.org/configuration/options#session"},
			},
			Metadata: map[string]any{
				"cookie_name":          cookieName,
				"sensitive_claims":     foundSensitive,
				"substantive_claims":   substantiveClaims,
				"substantive_values":   len(substantiveClaims) > 0,
				"credential_validated": false,
			},
		},
	}
}

func isSubstantiveClaimValue(value any, depth int) bool {
	if depth > 3 || value == nil {
		return false
	}

	switch typed := value.(type) {
	case string:
		value := strings.TrimSpace(typed)
		if len(value) < 8 || modkit.IsPlaceholderValue(value) {
			return false
		}
		lower := strings.ToLower(value)
		for _, marker := range []string{
			"example", "placeholder", "changeme", "change-me", "dummy", "sample",
			"redacted", "masked", "your_", "your-", "<secret", "${", "{{",
		} {
			if strings.Contains(lower, marker) {
				return false
			}
		}
		trimmedMask := strings.Trim(value, "*xX.-_ ")
		return trimmedMask != ""
	case []any:
		for _, item := range typed {
			if isSubstantiveClaimValue(item, depth+1) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if isSubstantiveClaimValue(item, depth+1) {
				return true
			}
		}
	}

	// Booleans and numbers under a security-looking key commonly represent
	// feature flags or identifiers; the key alone remains an observation.
	return false
}
