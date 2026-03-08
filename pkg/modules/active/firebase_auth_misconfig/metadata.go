package firebase_auth_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-firebase-auth-misconfig"
	ModuleName  = "Firebase Auth Misconfiguration"
	ModuleShort = "Detects Firebase Authentication misconfigurations via Identity Toolkit probing"
)

var (
	ModuleDesc = `## Description
Extracts Firebase API keys from crawled responses and probes the Identity
Toolkit API for authentication misconfigurations including anonymous signup,
email enumeration, unrestricted API keys, and weak password policies.

## Notes
- Extracts apiKey from Firebase config in HTML/JS responses
- Tests anonymous authentication (signUp without email/password)
- Tests email enumeration via signInWithPassword error differentiation
- Tests unrestricted API key usage from scanner origin
- Cleans up any test accounts created during scanning
- Deduplicates by API key to avoid redundant probing

## References
- https://firebase.google.com/docs/auth/web/start
- https://cloud.google.com/identity-platform/docs/reference/rest`

	ModuleConfirmation = "Confirmed when Identity Toolkit endpoints respond with auth tokens or distinguishable error codes indicating misconfiguration"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "auth-bypass", "moderate"}
)
