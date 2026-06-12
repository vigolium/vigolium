package cookie_security_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cookie-security-detect"
	ModuleName  = "Cookie Security Detect"
	ModuleShort = "Detects insecure cookie attributes in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A Set-Cookie header in the response sets a cookie that is missing one or more hardening attributes: Secure (on HTTPS responses), HttpOnly, or SameSite. Without these, the cookie, often a session token, is more exposed to theft and cross-site abuse, weakening the protection of any authenticated session it represents.

**How it's exploited:** A cookie without HttpOnly can be read by injected JavaScript, so an XSS flaw can exfiltrate the session token and let an attacker hijack the account. Without Secure, the cookie can be sent over plain HTTP and captured by a network attacker. Without SameSite, the browser attaches the cookie to cross-site requests, enabling cross-site request forgery (CSRF) against state-changing actions.

**Fix:** Set Secure, HttpOnly, and an explicit SameSite (Lax or Strict) on all session and sensitive cookies, scoped with a restrictive Path and Domain.`

	ModuleConfirmation = "Confirmed when Set-Cookie headers lack Secure, HttpOnly, or SameSite attributes"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"session", "misconfiguration", "header-security", "light"}
)
