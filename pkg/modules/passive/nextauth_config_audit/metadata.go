package nextauth_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-nextauth-config-audit"
	ModuleName  = "NextAuth.js Configuration Audit"
	ModuleShort = "Detects insecure NextAuth.js session and cookie configurations"
)

var (
	ModuleDesc = `## Description
Inspects HTTP responses for NextAuth.js (Auth.js) session configuration issues.
Checks session cookies for missing security flags, decodes JWT session tokens to
detect sensitive data exposure, and fingerprints NextAuth API endpoints for
information leakage.

## Notes
- Detects NextAuth session cookies (next-auth.session-token, __Secure-next-auth.*)
- Checks cookie flags: Secure, HttpOnly, SameSite
- Decodes JWT payloads to detect sensitive claims (passwords, secrets, tokens)
- Fingerprints NextAuth endpoints via response patterns
- Deduplicates by host

## References
- https://next-auth.js.org/configuration/options
- https://next-auth.js.org/configuration/options#cookies
- https://authjs.dev/getting-started/session-management/protecting`

	ModuleConfirmation = "Confirmed when NextAuth session cookies have insecure flags or JWT tokens contain sensitive data"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "authentication", "session", "light"}
)
