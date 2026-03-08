package sensitive_api_fields_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-api-fields-detect"
	ModuleName  = "Sensitive API Fields Detect"
	ModuleShort = "Flags JSON API responses containing sensitive field names like passwords, API keys, and PII"
)

var (
	ModuleDesc = `## Description
Passively analyzes JSON API responses for field names that indicate sensitive
data exposure. Checks for password fields, API keys, access tokens, private
keys, SSNs, and credit card numbers. Skips API documentation and JSON Schema
responses to reduce false positives.

## Notes
- Passive only: does not send any HTTP requests
- Only operates on application/json responses
- Uses quoted field name matching to avoid false positives in prose
- Skips OpenAPI/Swagger docs and JSON Schema responses
- Deduplicates by host to avoid flooding with the same finding

## References
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`

	ModuleConfirmation = "Confirmed when JSON response body contains sensitive field names"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"api", "info-disclosure", "light"}
)
