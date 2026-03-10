package api_version_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-version-detect"
	ModuleName  = "API Version Detect"
	ModuleShort = "Detects API versioning patterns in URLs, headers, and response bodies"
)

var (
	ModuleDesc = `## Description
Passively detects API version indicators in HTTP traffic including URL path patterns,
version headers, and version fields in JSON response bodies.

## Notes
- Detects version patterns in URL paths (e.g., /v1/, /api/v2/)
- Checks for version-related response headers (API-Version, X-API-Version, Accept-Version)
- Parses JSON response bodies for version fields
- Useful for API enumeration and identifying deprecated API versions

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/`

	ModuleConfirmation = "Confirmed when URL path, headers, or response body contain API version indicators"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"api", "fingerprint", "light"}
)
