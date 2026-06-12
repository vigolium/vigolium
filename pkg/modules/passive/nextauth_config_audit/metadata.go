package nextauth_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextauth-config-audit"
	ModuleName  = "NextAuth.js Configuration Audit"
	ModuleShort = "Detects insecure NextAuth.js session and cookie configurations"
)

var (
	ModuleDesc = `**What it means:** A NextAuth.js (Auth.js) session cookie was set with weak security attributes, or its JWT session token carries sensitive data in plain view. This module flags two issues: session cookies missing the Secure, HttpOnly, or SameSite attributes (or SameSite=None without Secure), and JWT session tokens whose base64-decoded payload contains sensitive claim names such as password, secret, access_token, or db_password. JWTs are signed but not encrypted, so any party holding the token can read these values.

**How it's exploited:** A missing HttpOnly flag lets cross-site scripting steal the session cookie; a missing Secure flag exposes it over plaintext HTTP; a weak or absent SameSite attribute enables CSRF or cross-site session leakage. If the JWT embeds credentials or tokens, anyone who captures the cookie (via XSS, logs, or a shared device) can decode it to harvest those secrets and impersonate the user or pivot to other systems.

**Fix:** Set Secure, HttpOnly, and SameSite=Lax/Strict on NextAuth cookies, and keep passwords, secrets, and access tokens out of the JWT session payload.`

	ModuleConfirmation = "Confirmed when NextAuth session cookies have insecure flags or JWT tokens contain sensitive data"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "session", "light"}
)
