package csrf_verify

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-verify"
	ModuleName  = "CSRF Token Verification"
	ModuleShort = "Verifies CSRF token enforcement by removing, emptying, or randomizing tokens"
)

var (
	ModuleDesc = `## Description
For requests that contain a CSRF token, this module verifies whether the server
actually enforces it. It removes, empties, or randomizes the token value and
checks if the server still accepts the request.

## Notes
- Only targets requests that already have a CSRF token parameter
- Three probe strategies: token removed, token emptied, token randomized
- Stops probing early if the server returns 4xx/5xx (properly validated)
- Deduplicates by method + host + path

## References
- https://owasp.org/www-community/attacks/csrf
- https://portswigger.net/web-security/csrf/bypassing-token-validation`

	ModuleConfirmation = "Confirmed when the server accepts a request with a removed, emptied, or randomized CSRF token"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "audit", "moderate"}
)
