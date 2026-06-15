package clickjacking_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// maxBodyScan caps how many leading bytes of the body are inspected for
// interactive content. Forms and controls relevant to clickjacking live in the
// rendered markup; the cap keeps the regex passes cheap on large pages.
const maxBodyScan = 512 << 10

var (
	// formOpenRe matches an opening <form ...> tag (used to extract method/action).
	formOpenRe = regexp.MustCompile(`(?i)<form\b[^>]*>`)
	// passwordFieldRe matches an HTML password input — the strongest "worth
	// hijacking" signal (login / credential / change-password forms).
	passwordFieldRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password["']?[^>]*>`)
	// submitControlRe matches a clickable submit/button control.
	submitControlRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?(submit|image|button)["']?|<button\b`)
	// methodAttrRe / actionAttrRe extract the method and action of a form tag.
	methodAttrRe = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?([a-zA-Z]+)`)
	actionAttrRe = regexp.MustCompile(`(?i)\baction\s*=\s*["']?([^"'\s>]+)`)
	// sensitivePathRe matches a form action that targets a state-changing or
	// account/security/financial endpoint. Deliberately narrow to avoid flagging
	// newsletter, search, and cookie-consent forms on marketing pages.
	sensitivePathRe = regexp.MustCompile(`(?i)(login|logout|signin|sign-in|signout|sign-out|account|settings|profile|admin|password|passwd|credential|transfer|payment|billing|checkout|withdraw|deposit|delete|remove|revoke|grant|approve|disable|deactivate|2fa|mfa|/api/|graphql)`)
	// sessionCookieRe matches a session/auth cookie name (PHPSESSID, JSESSIONID,
	// connect.sid, laravel_session, access_token, id_token, …).
	sessionCookieRe = regexp.MustCompile(`(?i)(sess|sid|auth|token|jwt|sso|login)`)
	// csrfCookieRe excludes CSRF/XSRF tokens, which sessionCookieRe would
	// otherwise treat as a session because they contain "token".
	csrfCookieRe = regexp.MustCompile(`(?i)(csrf|xsrf)`)
)

// Module implements the clickjacking passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Clickjacking detection module.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_clickjacking_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost evaluates a response once per host for an exploitable clickjacking
// exposure: framable headers plus sensitive/interactive content.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	resp := ctx.Response()
	if resp == nil || ctx.Request() == nil {
		return nil, nil
	}

	// Status gate: only a real, rendered application page can be clickjacked.
	if resp.StatusCode() != 200 {
		return nil, nil
	}

	// Content gate: only HTML with a body can be framed into a UI-redress overlay.
	ct := strings.ToLower(resp.Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}
	body := resp.Body()
	if len(body) == 0 {
		return nil, nil
	}
	// Cap the byte slice before converting so the copy is bounded by maxBodyScan,
	// not the full body size (Body() is zero-copy; string() allocates).
	if len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	scan := string(body)

	// Block gate: drop a WAF/CDN challenge interstitial served with a 200.
	if modkit.IsEdgeBlockedResponse(resp) {
		return nil, nil
	}

	// Header verdict: is the page actually framable in a browser?
	framable, headerReason := framingVerdict(resp)
	if !framable {
		return nil, nil
	}

	// Interactive-content baseline: is the page worth hijacking? Static framable
	// pages are deferred to security_headers_missing / csp_weakness_audit.
	content := analyzeContent(scan, ctx.Request(), resp)
	sev, contentReason, ok := classifyTier(content)
	if !ok {
		return nil, nil
	}

	// SameSite modifier: a Strict/Lax session cookie is withheld on a cross-site
	// iframe load, so the framed page is unauthenticated — downgrade.
	sameSiteNote := ""
	if sev == severity.Medium && content.sessionSameSiteProtected {
		sev = severity.Low
		sameSiteNote = "; session cookie is SameSite=" + content.sessionSameSiteValue +
			" so the cross-site frame loads unauthenticated (downgraded)"
	}

	// Dedup per host (test-and-set).
	if diskSet := m.ds.Get(scanCtx.DedupMgr()); diskSet != nil && diskSet.IsSeen(service.Host()) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	target := urlx.String()

	desc := fmt.Sprintf(
		"The page is framable in a cross-origin iframe (%s) and carries %s%s. "+
			"An attacker can overlay a transparent iframe of this page on a decoy "+
			"site and hijack the victim's clicks (UI redress). Set "+
			"`Content-Security-Policy: frame-ancestors 'none'` (or 'self') and "+
			"`X-Frame-Options: DENY`/`SAMEORIGIN`.\n\nProof-of-concept overlay:\n"+
			"<style>iframe{position:absolute;top:0;left:0;width:100%%;height:100%%;opacity:0.0001;z-index:2}</style>\n"+
			"<iframe src=\"%s\"></iframe>",
		headerReason, contentReason, sameSiteNote, target,
	)

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     service.Host(),
			URL:      target,
			Matched:  target,
			Request:  string(ctx.Request().Raw()),
			ExtractedResults: []string{
				"Framing: " + headerReason,
				"Content: " + contentReason,
			},
			Info: output.Info{
				Name:        "Clickjacking: framable page with " + contentSummary(content),
				Description: desc,
				Severity:    sev,
				Confidence:  severity.Firm,
				Tags:        []string{"clickjacking", "ui-redress", "header-security"},
				Reference: []string{
					"https://owasp.org/www-community/attacks/Clickjacking",
					"https://portswigger.net/web-security/clickjacking",
					"https://cwe.mitre.org/data/definitions/1021.html",
				},
			},
			Metadata: map[string]any{
				"cwe":            "CWE-1021",
				"framing_reason": headerReason,
			},
		},
	}, nil
}

// framingVerdict reports whether resp can be framed cross-origin, applying
// browser precedence: an enforced CSP frame-ancestors directive overrides
// X-Frame-Options. The returned string explains why the page is framable.
func framingVerdict(resp *httpmsg.HttpResponse) (bool, string) {
	faPresent, faRestrictive, faValue := frameAncestors(resp)
	switch {
	case faRestrictive:
		return false, ""
	case faPresent:
		// frame-ancestors present but permissive — CSP wins, XFO ignored.
		return true, fmt.Sprintf("CSP frame-ancestors is permissive (%q), which overrides X-Frame-Options", faValue)
	}

	// No enforced frame-ancestors anywhere — fall back to X-Frame-Options.
	protected, xfoReason := xfoVerdict(resp)
	if protected {
		return false, ""
	}
	return true, xfoReason
}

// frameAncestors inspects every enforced (non report-only) CSP header and
// reports whether a frame-ancestors directive is present and whether any one of
// them restricts framing (the most-restrictive policy wins under CSP
// intersection semantics).
func frameAncestors(resp *httpmsg.HttpResponse) (present, restrictive bool, permissiveValue string) {
	for _, h := range resp.Headers() {
		if !strings.EqualFold(h.Name, "Content-Security-Policy") {
			continue // report-only does not enforce; skip everything else
		}
		val, ok := directiveValue(h.Value, "frame-ancestors")
		if !ok {
			continue
		}
		present = true
		if frameAncestorsRestrictive(val) {
			restrictive = true
			return // a single restrictive policy protects the page
		}
		permissiveValue = strings.TrimSpace(val)
	}
	return present, restrictive, permissiveValue
}

// directiveValue extracts a directive's value from a CSP header string.
func directiveValue(csp, name string) (string, bool) {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, " ", 2)
		if !strings.EqualFold(strings.TrimSpace(fields[0]), name) {
			continue
		}
		if len(fields) == 1 {
			return "", true // bare directive == empty source list
		}
		return strings.TrimSpace(fields[1]), true
	}
	return "", false
}

// frameAncestorsRestrictive reports whether a frame-ancestors value restricts
// cross-origin framing. An empty source list ('none' / bare directive) and a
// specific allowlist are restrictive; a bare '*' or a scheme-only source allows
// any origin and is not.
func frameAncestorsRestrictive(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return true // empty source list matches nothing — like 'none'
	}
	if strings.Contains(v, "'none'") {
		return true
	}
	for _, tok := range strings.Fields(v) {
		if tok == "*" || tok == "http:" || tok == "https:" || tok == "ws:" || tok == "wss:" {
			return false
		}
	}
	return true
}

// xfoVerdict evaluates X-Frame-Options. It is only consulted when no enforced
// CSP frame-ancestors directive is present.
func xfoVerdict(resp *httpmsg.HttpResponse) (protected bool, reason string) {
	var values []string
	for _, h := range resp.Headers() {
		if strings.EqualFold(h.Name, "X-Frame-Options") {
			// A single header may itself carry a comma-combined value.
			for _, part := range strings.Split(h.Value, ",") {
				if p := strings.TrimSpace(part); p != "" {
					values = append(values, p)
				}
			}
		}
	}

	if len(values) == 0 {
		return false, "no X-Frame-Options and no CSP frame-ancestors header"
	}
	if len(values) > 1 {
		// Duplicated / conflicting directives — browsers discard the header.
		return false, fmt.Sprintf("conflicting X-Frame-Options values (%s) are ignored by browsers", strings.Join(values, ", "))
	}

	v := strings.ToUpper(strings.TrimSpace(values[0]))
	switch {
	case v == "DENY", v == "SAMEORIGIN":
		return true, ""
	case strings.HasPrefix(v, "ALLOW-FROM"):
		return false, "X-Frame-Options uses deprecated ALLOW-FROM, ignored by modern browsers"
	default:
		return false, fmt.Sprintf("X-Frame-Options has an invalid value (%q)", values[0])
	}
}

// contentSignals captures the interactive/sensitive characteristics of a page.
type contentSignals struct {
	requestAuthenticated     bool // captured traffic carried a session cookie / Authorization
	responseSetsSession      bool // response sets a session-like cookie
	interactiveControl       bool // a form, submit, or button is present
	credentialForm           bool // a password field is present
	statePostForm            bool // a POST form is present
	sensitivePathForm        bool // a form posts to a sensitive/account/financial endpoint
	sessionSameSiteProtected bool // the session Set-Cookie is SameSite=Strict/Lax
	sessionSameSiteValue     string
}

// analyzeContent inspects the body and request/response headers for the signals
// that make a framable page worth hijacking.
func analyzeContent(body string, req *httpmsg.HttpRequest, resp *httpmsg.HttpResponse) contentSignals {
	var c contentSignals

	c.credentialForm = passwordFieldRe.MatchString(body)

	forms := formOpenRe.FindAllString(body, -1)
	for _, form := range forms {
		if m := methodAttrRe.FindStringSubmatch(form); m != nil && strings.EqualFold(m[1], "post") {
			c.statePostForm = true
		}
		if a := actionAttrRe.FindStringSubmatch(form); a != nil && sensitivePathRe.MatchString(a[1]) {
			c.sensitivePathForm = true
		}
	}
	c.interactiveControl = len(forms) > 0 || submitControlRe.MatchString(body)

	// Request-side auth: the captured page was loaded with credentials.
	if strings.TrimSpace(req.Header("Authorization")) != "" {
		c.requestAuthenticated = true
	} else if hasSessionCookie(req.Header("Cookie")) {
		c.requestAuthenticated = true
	}

	// Response-side session establishment + SameSite posture.
	for _, h := range resp.Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		name, sameSite := parseSetCookie(h.Value)
		if !isSessionName(name) {
			continue
		}
		c.responseSetsSession = true
		if ss := strings.ToLower(sameSite); ss == "strict" || ss == "lax" {
			c.sessionSameSiteProtected = true
			c.sessionSameSiteValue = strings.TrimSpace(sameSite)
		}
	}

	return c
}

// classifyTier maps content signals to a severity tier, or reports ok=false to
// drop a framable-but-static page (deferred to the hygiene modules).
func classifyTier(c contentSignals) (severity.Severity, string, bool) {
	authContext := c.requestAuthenticated || c.responseSetsSession

	// Medium: an authenticated framable page with clickable actions, or an auth
	// context combined with a clearly state-changing/credential form. The first
	// branch deliberately requires requestAuthenticated (a live in-frame session),
	// not authContext — a response merely setting a cookie is not enough on its own.
	if c.requestAuthenticated && c.interactiveControl {
		return severity.Medium, "an authenticated session with interactive controls (state-changing clicks can be hijacked)", true
	}
	if authContext && (c.credentialForm || c.sensitivePathForm || c.statePostForm) {
		return severity.Medium, "an authenticated context and a state-changing form", true
	}

	// Low: a credential form (login clickjacking) or a form posting to a
	// sensitive endpoint, even without an observed auth session.
	if c.credentialForm {
		return severity.Low, "a credential (password) form vulnerable to login/UI-redress", true
	}
	if c.sensitivePathForm {
		return severity.Low, "a form posting to a sensitive/account endpoint", true
	}

	return severity.Info, "", false
}

// contentSummary returns a short label for the finding name.
func contentSummary(c contentSignals) string {
	switch {
	case c.credentialForm:
		return "a credential form"
	case c.requestAuthenticated || c.responseSetsSession:
		return "authenticated interactive content"
	case c.sensitivePathForm:
		return "a sensitive-action form"
	default:
		return "interactive content"
	}
}

// hasSessionCookie reports whether a request Cookie header carries a
// session/auth cookie.
func hasSessionCookie(cookieHeader string) bool {
	for _, pair := range strings.Split(cookieHeader, ";") {
		name := strings.TrimSpace(pair)
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if isSessionName(name) {
			return true
		}
	}
	return false
}

// isSessionName reports whether a cookie name looks like a session/auth cookie,
// excluding CSRF/XSRF tokens.
func isSessionName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || csrfCookieRe.MatchString(name) {
		return false
	}
	return sessionCookieRe.MatchString(name)
}

// parseSetCookie returns the cookie name and SameSite attribute from a
// Set-Cookie header value.
func parseSetCookie(value string) (name, sameSite string) {
	parts := strings.Split(value, ";")
	if len(parts) == 0 {
		return "", ""
	}
	if i := strings.IndexByte(parts[0], '='); i >= 0 {
		name = strings.TrimSpace(parts[0][:i])
	}
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		if eq := strings.IndexByte(attr, '='); eq >= 0 && strings.EqualFold(strings.TrimSpace(attr[:eq]), "samesite") {
			sameSite = strings.TrimSpace(attr[eq+1:])
		}
	}
	return name, sameSite
}
