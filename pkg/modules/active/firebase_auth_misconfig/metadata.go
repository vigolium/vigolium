package firebase_auth_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-auth-misconfig"
	ModuleName  = "Firebase Auth Misconfiguration"
	ModuleShort = "Detects Firebase Authentication misconfigurations via Identity Toolkit probing"
)

var (
	ModuleDesc = `**What it means:** A Firebase apiKey exposed in the page or JavaScript links to a misconfigured Identity Toolkit project: anonymous sign-in is enabled, login errors confirm registered emails, or createAuthUri reveals whether an account exists and its providers.

**How it's exploited:** An attacker reuses the public key against identitytoolkit.googleapis.com to mint anonymous tokens that may satisfy auth != null rules and reach protected data, and to enumerate accounts for phishing or account takeover.

**Fix:** Disable unused anonymous sign-in, enable email-enumeration protection, restrict the API key by referrer or app, and enforce rules that distrust anonymous accounts.`

	ModuleConfirmation = "Confirmed when Identity Toolkit endpoints respond with auth tokens or distinguishable error codes indicating misconfiguration"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "auth-bypass", "moderate"}
)
