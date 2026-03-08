package csrf_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-csrf-detect"
	ModuleName  = "CSRF Detection"
	ModuleShort = "Flags state-changing requests missing anti-CSRF protections"
)

var (
	ModuleDesc = `## Description
Detects state-changing HTTP requests (POST, PUT, DELETE, PATCH) that lack common
anti-CSRF protections such as CSRF tokens in parameters/headers or SameSite cookie
attributes.

## Notes
- Passive only — does not send any HTTP requests
- Skips JSON API requests with Origin header (CORS-protected)
- Checks for CSRF tokens in body parameters, custom headers, and SameSite cookies
- Deduplicates by method + host + path

## References
- https://owasp.org/www-community/attacks/csrf
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html`

	ModuleConfirmation = "Indicated when a state-changing request lacks CSRF token parameters, custom anti-CSRF headers, and SameSite cookie attributes"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"csrf", "session", "light"}
)
