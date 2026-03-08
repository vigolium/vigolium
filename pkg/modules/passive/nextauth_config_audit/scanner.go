package nextauth_config_audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
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
		cookieLower := strings.ToLower(cookie)

		// Check if this is a NextAuth cookie
		var matchedName string
		for _, name := range nextAuthCookieNames {
			if strings.HasPrefix(cookieLower, name+"=") {
				matchedName = name
				break
			}
		}
		if matchedName == "" {
			continue
		}

		// Check cookie security flags
		var issues []string

		if isHTTPS && !strings.Contains(cookieLower, "secure") {
			issues = append(issues, "Missing Secure flag on HTTPS")
		}

		if !strings.Contains(cookieLower, "httponly") {
			issues = append(issues, "Missing HttpOnly flag")
		}

		if !strings.Contains(cookieLower, "samesite") {
			issues = append(issues, "Missing SameSite attribute")
		} else if strings.Contains(cookieLower, "samesite=none") && !strings.Contains(cookieLower, "secure") {
			issues = append(issues, "SameSite=None without Secure flag")
		}

		if len(issues) > 0 {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     urlx.Host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Cookie: %s", matchedName),
					fmt.Sprintf("Issues: %s", strings.Join(issues, "; ")),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("NextAuth.js Insecure Cookie: %s", matchedName),
					Description: fmt.Sprintf("NextAuth session cookie %q has insecure configuration: %s", matchedName, strings.Join(issues, "; ")),
					Severity:    severity.Medium,
					Confidence:  severity.Firm,
					Tags:        []string{"nextauth", "cookies", "session-management"},
					Reference:   []string{"https://next-auth.js.org/configuration/options#cookies"},
				},
				Metadata: map[string]any{
					"cookie_name": matchedName,
					"issues":      issues,
				},
			})
		}

		// For session tokens, attempt JWT decode to check for sensitive claims
		if strings.Contains(matchedName, "session-token") {
			if sensitiveResults := m.checkJWTClaims(cookie, matchedName, urlx.Host, urlx.String()); len(sensitiveResults) > 0 {
				results = append(results, sensitiveResults...)
			}
		}
	}

	return results, nil
}

// checkJWTClaims decodes a JWT session token and checks for sensitive claims.
func (m *Module) checkJWTClaims(cookie, cookieName, host, url string) []*output.ResultEvent {
	// Extract token value from cookie
	parts := strings.SplitN(cookie, "=", 2)
	if len(parts) < 2 {
		return nil
	}
	tokenValue := parts[1]
	if idx := strings.Index(tokenValue, ";"); idx > 0 {
		tokenValue = tokenValue[:idx]
	}
	tokenValue = strings.TrimSpace(tokenValue)

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

	// Check for sensitive claim names
	var foundSensitive []string
	for key := range claims {
		keyLower := strings.ToLower(key)
		for _, sensitive := range sensitiveClaims {
			if strings.Contains(keyLower, sensitive) {
				foundSensitive = append(foundSensitive, key)
				break
			}
		}
	}

	if len(foundSensitive) == 0 {
		return nil
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     host,
			URL:      url,
			Matched:  url,
			ExtractedResults: []string{
				fmt.Sprintf("Cookie: %s", cookieName),
				fmt.Sprintf("Sensitive JWT claims: %s", strings.Join(foundSensitive, ", ")),
			},
			Info: output.Info{
				Name:        "NextAuth.js JWT Sensitive Data Exposure",
				Description: fmt.Sprintf("NextAuth JWT session token contains sensitive claims: %s. JWTs are only signed, not encrypted — these values are visible to anyone with the token.", strings.Join(foundSensitive, ", ")),
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"nextauth", "jwt", "information-disclosure"},
				Reference:   []string{"https://next-auth.js.org/configuration/options#session"},
			},
			Metadata: map[string]any{
				"cookie_name":      cookieName,
				"sensitive_claims": foundSensitive,
			},
		},
	}
}
