package forbidden_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "forbidden-bypass"
	ModuleName  = "403/401 Forbidden Bypass"
	ModuleShort = "Detects bypass methods for 403/401 Forbidden responses"
)

var (
	ModuleDesc = `## Description
Tests various techniques to bypass 403 Forbidden and 401 Unauthorized responses, including path manipulation,
header injection, HTTP method tampering, method override headers, and URL encoding tricks.

## Notes
- Only activates when the original response returns 401 or 403 status
- Tests multiple bypass vectors: path traversal, special headers, HTTP method changes, method override headers

## References
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/403-and-401-bypasses.html`

	ModuleConfirmation = "Confirmed when a bypass technique produces a non-403 response with valid content for a previously forbidden resource"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
