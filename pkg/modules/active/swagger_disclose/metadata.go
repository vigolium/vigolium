package swagger_disclose

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "swagger-disclose"
	ModuleName  = "Swagger Disclosure"
	ModuleShort = "Detects exposed Swagger/OpenAPI documentation"
)

var (
	ModuleDesc = `## Description
Detects exposed Swagger/OpenAPI documentation endpoints that may reveal internal
API structure, endpoints, and parameter details.

## Notes
- Checks common Swagger paths (/swagger.json, /api-docs, /swagger-ui.html, etc.)
- Runs per-request to detect documentation exposure
- Exposed API docs can reveal hidden endpoints and internal architecture

## References
- https://swagger.io/specification/`

	ModuleConfirmation = "Confirmed when Swagger/OpenAPI documentation endpoints return valid API specification content"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
