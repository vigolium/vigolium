package insecure_token_storage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-insecure-token-storage"
	ModuleName  = "Insecure Token Storage"
	ModuleShort = "Detects auth tokens stored in localStorage/sessionStorage"
)

var (
	ModuleDesc = `## Description
Scans JavaScript response bodies for patterns that store authentication tokens,
API keys, or session identifiers in browser localStorage or sessionStorage.
Storing sensitive tokens in Web Storage exposes them to XSS attacks -- any
script running in the same origin can read these values, making token theft
trivial if an XSS vulnerability exists.

## Notes
- Passive only -- does not send any HTTP requests
- Detects setItem calls with known auth-related key names
- Detects bracket notation assignment to known auth key names
- Flags patterns that read from localStorage for Authorization headers (higher severity)
- Deduplicates by host+path

## References
- https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/922.html
- https://auth0.com/docs/secure/security-guidance/data-security/token-storage`

	ModuleConfirmation = "Confirmed when JavaScript code stores auth tokens or secrets in localStorage or sessionStorage"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"authentication", "session", "javascript", "light"}
)
