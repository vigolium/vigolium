package nextauth_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextauth-config-audit"
	ModuleName  = "NextAuth.js Configuration Audit"
	ModuleShort = "Detects insecure NextAuth.js session and cookie configurations"
)

var (
	ModuleDesc = `**What it means:** A NextAuth.js (Auth.js) session cookie is set without Secure, HttpOnly, or SameSite, or its JWT payload carries sensitive claim names like password, secret, or access_token. JWTs are signed but not encrypted, so any holder can read these values.

**How it's exploited:** Missing HttpOnly lets XSS steal the cookie; missing Secure exposes it over HTTP; weak SameSite enables CSRF. If the JWT embeds credentials, anyone who captures the cookie can decode it and impersonate the user.

**Fix:** Set Secure, HttpOnly, and SameSite=Lax/Strict on NextAuth cookies, and keep secrets out of the JWT payload.`

	ModuleConfirmation = "Confirmed when NextAuth session cookies have insecure flags or JWT tokens contain sensitive data"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "session", "light"}
)
