package csrf_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// csrfParamPattern matches common CSRF token parameter names. The bare token
// alternative is anchored with word boundaries (\btoken\b) so it matches a field
// literally named "token" but NOT camelCase application fields whose name merely
// ends in "Token" (accessToken, siteToken, tokenCount, …) — those must not
// suppress a genuine missing-token finding. Literal separators in dotted names
// are escaped (authenticity[._-]?token) rather than left as wildcard dots.
var csrfParamPattern = regexp.MustCompile(`(?i)(csrf|xsrf|\btoken\b|authenticity[._-]?token|__RequestVerificationToken|antiforgery|_token|nonce|csrfmiddlewaretoken)`)

// csrfHeaderPattern matches custom headers used for CSRF protection.
var csrfHeaderPattern = regexp.MustCompile(`(?i)^(x-csrf-token|x-xsrf-token|x-requested-with|x-csrftoken|anti-csrf-token)$`)

// sameSitePattern matches SameSite cookie attribute with Strict or Lax.
var sameSitePattern = regexp.MustCompile(`(?i)samesite=(strict|lax)`)

// stateChangingMethods are HTTP methods that modify server state.
var stateChangingMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
}

// Module implements passive CSRF detection.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSRF detection passive module.
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
		ds: dedup.LazyDiskSet("csrf_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// isCSRFReachableContentType reports whether a cross-site HTML form / simple
// fetch could produce a request with this Content-Type without triggering a CORS
// preflight. Only the three CORS "simple" content types (and an absent header,
// which a form defaults to form-urlencoded) qualify; anything else — notably
// application/json — cannot be forged cross-site by classic CSRF.
func isCSRFReachableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return true
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 { // drop "; charset=…" / "; boundary=…"
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}

// ScanPerRequest analyzes state-changing requests for missing CSRF protections.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only check state-changing methods
	method := strings.ToUpper(ctx.Request().Method())
	if !stateChangingMethods[method] {
		return nil, nil
	}

	// CSRF preconditions: the attack only works against requests a browser will
	// replay cross-site using AMBIENT credentials. A "missing token" on a request
	// that fails any of these is not a vulnerability, so skip it rather than
	// flagging it (the reported false positives: JSON APIs, Bearer-token APIs, and
	// requests with no session cookie).
	//
	//  1. A non-simple content type (e.g. application/json) cannot be produced by a
	//     cross-site HTML form and forces a CORS preflight — not classic CSRF.
	//  2. Header-based auth (Authorization: Bearer/Basic …) is never attached
	//     automatically cross-site, so the endpoint is not CSRF-able.
	//  3. No ambient SESSION cookie means there is no session for an attacker to
	//     ride, so a missing anti-CSRF token is moot. A request carrying only a
	//     preference cookie (e.g. theme=dark) does not count.
	if !isCSRFReachableContentType(ctx.Request().Header("Content-Type")) {
		return nil, nil
	}
	if ctx.Request().Header("Authorization") != "" {
		return nil, nil
	}
	hasSessionCookie := false
	for _, name := range modkit.RequestCookieNames(ctx.Request().Header("Cookie")) {
		if modkit.LikelySessionCookie(name) {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		return nil, nil
	}

	// Dedup by method:host:path
	dedupKey := utils.Sha1(fmt.Sprintf("%s:%s:%s", method, urlx.Host, urlx.Path))
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Check 1: CSRF token in parameters
	params, err := ctx.Request().Parameters()
	if err == nil {
		for _, param := range params {
			if csrfParamPattern.MatchString(param.Name()) {
				return nil, nil // has CSRF token
			}
		}
	}

	// Check 2: CSRF header
	rawReq := string(ctx.Request().Raw())
	for _, line := range strings.Split(rawReq, "\n") {
		if idx := strings.Index(line, ":"); idx > 0 {
			headerName := strings.TrimSpace(line[:idx])
			if csrfHeaderPattern.MatchString(headerName) {
				return nil, nil // has CSRF header
			}
		}
	}

	// Check 3: SameSite protection on the SESSION cookie the request actually
	// carries. The protective SameSite attribute is set on the login response and
	// is normally NOT echoed on this state-changing response, so consult the
	// recorded policy for the request's own session cookie rather than this
	// response's Set-Cookie headers (which may carry only an unrelated preference
	// cookie, producing both false positives and false negatives).
	scanCtx.ObserveResponseCookies(ctx)
	for _, policy := range scanCtx.RequestCookiePolicies(ctx) {
		if !modkit.LikelySessionCookie(policy.Name) {
			continue
		}
		if policy.SameSite == "strict" || policy.SameSite == "lax" {
			return nil, nil // session cookie is SameSite-protected
		}
	}

	// No CSRF protection found
	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			Info: output.Info{
				Name:        "Missing CSRF Protection",
				Description: fmt.Sprintf("State-changing %s request to %s lacks anti-CSRF token, custom header, and SameSite cookie protection", method, urlx.Path),
				Severity:    severity.Medium,
				Confidence:  severity.Tentative,
				Tags:        []string{"csrf", "session", "web-security"},
				Reference:   []string{"https://owasp.org/www-community/attacks/csrf"},
			},
			Metadata: map[string]any{
				"method": method,
				"path":   urlx.Path,
			},
		},
	}, nil
}
