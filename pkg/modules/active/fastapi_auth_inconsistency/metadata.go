package fastapi_auth_inconsistency

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-auth-inconsistency"
	ModuleName  = "FastAPI Auth Inconsistency"
	ModuleShort = "Fetches OpenAPI schema and finds unprotected operations"
)

var (
	ModuleDesc = `## Description
Fetches the FastAPI OpenAPI schema from /openapi.json and analyzes it for
authentication inconsistencies. Identifies operations that lack security
requirements, either because they explicitly opt out of global security
or because no security is defined at any level.

## Notes
- Runs once per host
- Parses /openapi.json for OpenAPI spec
- Flags operations under /api prefix without security requirements
- Optionally verifies by calling endpoints without auth
- FA-02: FastAPI auth inconsistency detection

## References
- https://fastapi.tiangolo.com/tutorial/security/`

	ModuleConfirmation = "Confirmed when OpenAPI spec reveals operations without security requirements, optionally verified by unauthenticated access"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "auth-bypass", "audit", "moderate"}
)
