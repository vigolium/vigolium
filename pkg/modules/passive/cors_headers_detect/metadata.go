package cors_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-headers-detect"
	ModuleName  = "CORS Headers Detect"
	ModuleShort = "Passively detects permissive CORS headers in responses"
)

var (
	ModuleDesc = `## Description
Passively detects permissive CORS configurations by analyzing Access-Control-Allow-Origin
and related headers in HTTP responses without sending additional requests.

## Notes
- Flags wildcard (*) CORS origins
- Flags CORS with credentials enabled
- Complements the active CORS misconfiguration module with passive detection
- Runs per-request for comprehensive coverage

## References
- https://portswigger.net/web-security/cors
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS`

	ModuleConfirmation = "Confirmed when response contains permissive CORS headers such as wildcard origin or credentials enabled"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
