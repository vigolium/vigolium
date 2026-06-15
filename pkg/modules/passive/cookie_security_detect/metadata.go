package cookie_security_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cookie-security-detect"
	ModuleName  = "Cookie Security Detect"
	ModuleShort = "Detects insecure cookie attributes in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A Set-Cookie header omits a hardening attribute - Secure (on HTTPS), HttpOnly, or SameSite - leaving the cookie, often a session token, exposed to theft and cross-site abuse.

**How it's exploited:** Without HttpOnly, XSS-injected JavaScript can steal the token and hijack the account. Without Secure, the cookie travels over plain HTTP for a network attacker to capture. Without SameSite, the browser attaches it to cross-site requests, enabling CSRF.

**Fix:** Set Secure, HttpOnly, and an explicit SameSite (Lax or Strict) on all session and sensitive cookies, scoped with a restrictive Path and Domain.`

	ModuleConfirmation = "Confirmed when Set-Cookie headers lack Secure, HttpOnly, or SameSite attributes"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"session", "misconfiguration", "header-security", "light"}
)
