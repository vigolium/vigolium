package express_session_audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// maxSessionAge is the threshold above which a session Max-Age is considered
// excessive: 7 days in seconds.
const maxSessionAge = 604800

// sessionCookiePatterns lists common session cookie name prefixes/suffixes.
var sessionCookiePatterns = []string{"connect.sid", "sess", "session", "sid"}

// staticPathPrefixes lists path prefixes that indicate static/anonymous content.
var staticPathPrefixes = []string{
	"/static/", "/assets/", "/public/", "/dist/",
	"/css/", "/js/", "/img/", "/images/", "/fonts/",
	"/favicon", "/robots.txt", "/manifest.json",
}

// Module implements the Express Session Audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express Session Audit module.
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
		ds: dedup.LazyDiskSet("express_session_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes Set-Cookie headers for Express.js session security issues.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	host := urlx.Host

	// Host-level dedup — only audit once per host.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Collect Set-Cookie header values from response headers.
	var setCookies []string
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			setCookies = append(setCookies, h.Value)
		}
	}

	if len(setCookies) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, cookie := range setCookies {
		cookieName := extractCookieName(cookie)
		cookieLower := strings.ToLower(cookie)

		// Check 1: Default session name (connect.sid).
		if cookieName == "connect.sid" {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					"Default session cookie name: connect.sid",
					"Risk: Framework fingerprinting and identification",
				},
				Info: output.Info{
					Name:        "Default Express Session Name",
					Description: "The application uses the default connect.sid session cookie name, which reveals the Express.js/Connect framework and simplifies targeted attacks",
					Severity:    severity.Info,
					Confidence:  severity.Certain,
					Tags:        []string{"express", "session", "fingerprint", "default-config"},
				},
				Metadata: map[string]any{
					"cookie_name": cookieName,
					"issue":       "default-session-name",
				},
			})
		}

		// Check 2: Excessive session expiry via Max-Age.
		if maxAge, ok := extractMaxAge(cookieLower); ok && maxAge > maxSessionAge {
			days := maxAge / 86400
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Cookie: %s", cookieName),
					fmt.Sprintf("Max-Age: %d seconds (~%d days)", maxAge, days),
					fmt.Sprintf("Threshold: %d seconds (7 days)", maxSessionAge),
				},
				Info: output.Info{
					Name:        "Excessive Session Expiry",
					Description: fmt.Sprintf("Session cookie %q has Max-Age of %d seconds (~%d days), exceeding the recommended 7-day maximum", cookieName, maxAge, days),
					Severity:    severity.Medium,
					Confidence:  severity.Firm,
					Tags:        []string{"session", "expiry", "cookie", "misconfiguration"},
				},
				Metadata: map[string]any{
					"cookie_name": cookieName,
					"max_age":     maxAge,
					"issue":       "excessive-expiry",
				},
			})
		}

		// Check 3: Session proliferation — session cookie set on anonymous/static paths.
		if isSessionCookie(cookieName) && isStaticOrAnonymousPath(urlx.Path, ctx.Request().Method()) {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Session cookie: %s", cookieName),
					fmt.Sprintf("Path: %s", urlx.Path),
					"Issue: Session set on static/anonymous request",
				},
				Info: output.Info{
					Name:        "Session Proliferation Detected",
					Description: fmt.Sprintf("Session cookie %q is being set on a static or anonymous request (%s %s), which may cause unnecessary session creation and resource consumption", cookieName, ctx.Request().Method(), urlx.Path),
					Severity:    severity.Info,
					Confidence:  severity.Firm,
					Tags:        []string{"session", "proliferation", "performance", "misconfiguration"},
				},
				Metadata: map[string]any{
					"cookie_name": cookieName,
					"path":        urlx.Path,
					"method":      ctx.Request().Method(),
					"issue":       "session-proliferation",
				},
			})
		}
	}

	return results, nil
}

// extractCookieName extracts the cookie name from a Set-Cookie header value.
func extractCookieName(cookie string) string {
	name := cookie
	if idx := strings.Index(cookie, "="); idx > 0 {
		name = cookie[:idx]
	}
	return strings.TrimSpace(name)
}

// extractMaxAge parses the Max-Age directive from a lowercased Set-Cookie value.
// Returns the value in seconds and true if found and valid.
func extractMaxAge(cookieLower string) (int, bool) {
	idx := strings.Index(cookieLower, "max-age=")
	if idx < 0 {
		return 0, false
	}

	val := cookieLower[idx+len("max-age="):]
	// Trim to the next semicolon or end of string.
	if semi := strings.Index(val, ";"); semi >= 0 {
		val = val[:semi]
	}
	val = strings.TrimSpace(val)

	seconds, err := strconv.Atoi(val)
	if err != nil {
		return 0, false
	}
	return seconds, true
}

// isSessionCookie checks whether the cookie name matches common session patterns.
func isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range sessionCookiePatterns {
		if nameLower == pattern || strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// isStaticOrAnonymousPath returns true if the request path and method suggest
// a static or anonymous resource that should not need a session.
func isStaticOrAnonymousPath(path, method string) bool {
	if !strings.EqualFold(method, "GET") {
		return false
	}

	// Root path is considered anonymous.
	if path == "/" {
		return true
	}

	pathLower := strings.ToLower(path)
	for _, prefix := range staticPathPrefixes {
		if strings.HasPrefix(pathLower, prefix) {
			return true
		}
	}
	return false
}
