package firebase_auth_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-auth-misconfig"
	ModuleName  = "Firebase Auth Misconfiguration"
	ModuleShort = "Detects Firebase Authentication misconfigurations via Identity Toolkit probing"
)

var (
	ModuleDesc = `**What it means:** A publishable Firebase apiKey allowed selected Identity Toolkit behavior. Anonymous sign-in and a nonexistent-email error are observations; provider discovery is a candidate only when parsed data says registered:true and names providers.

**How it's exploited:** Anonymous tokens matter only if separate resource rules trust them. Email enumeration requires an existing-account differential. Firebase client API keys identify projects and are intentionally public, so key presence is never treated as a secret leak.

**Fix:** Disable unused anonymous sign-in, enable email-enumeration protection, restrict the API key by referrer or app, and enforce rules that distrust anonymous accounts.`

	ModuleConfirmation = "Observes supported auth behavior with structured responses; provider-discovery candidate requires registered:true plus non-empty methods, and protected access is never inferred from an anonymous token"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "auth-bypass", "moderate"}
)
