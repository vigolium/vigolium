package nextauth_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextauth-config-audit"
	ModuleName  = "NextAuth.js Configuration Audit"
	ModuleShort = "Detects insecure NextAuth.js session and cookie configurations"
)

var (
	ModuleDesc = `**What it means:** A NextAuth.js (Auth.js) session cookie lacks a browser security attribute, or a readable JWS-shaped session token contains a substantive value under a security-relevant claim. Name-only, empty, and redacted claims remain observations.

**How it's exploited:** Missing HttpOnly lets script read the session cookie; missing Secure permits cleartext transport; SameSite affects cross-site requests. Embedded credentials may expose an additional secret, but the scanner does not claim that credential is valid without provider or authorization proof.

**Fix:** Set Secure, HttpOnly, and SameSite=Lax/Strict on NextAuth cookies, and keep secrets out of the JWT payload.`

	ModuleConfirmation = "Confirmed for parsed session-cookie attribute defects; decoded substantive claim values are candidates until their sensitivity or impact is validated"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "session", "light"}
)
