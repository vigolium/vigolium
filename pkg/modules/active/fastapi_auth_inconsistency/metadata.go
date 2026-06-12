package fastapi_auth_inconsistency

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-auth-inconsistency"
	ModuleName  = "FastAPI Auth Inconsistency"
	ModuleShort = "Fetches OpenAPI schema and finds unprotected operations"
)

var (
	ModuleDesc = `**What it means:** The application is a FastAPI service that publishes its OpenAPI schema at /openapi.json, and one or more API operations under the /api prefix declare no authentication requirement. They either explicitly opt out of global security (security: []) or have no security defined at the operation or global level, so they are reachable without credentials. This is an access-control inconsistency that can expose sensitive endpoints to unauthenticated callers.
**How it's exploited:** An attacker reads the public OpenAPI schema to enumerate the unprotected operations, then calls those endpoints directly with no token, cookie, or API key. The scanner confirms exposure by replaying selected operations without authentication and observing a non-401/403 response, meaning data read/write actions intended for authenticated users may be performed by anyone.
**Fix:** Apply a consistent authentication dependency (for example a global security requirement or per-route auth dependency) to every API operation and remove any unintended security: [] overrides.`

	ModuleConfirmation = "Confirmed when OpenAPI spec reveals operations without security requirements, optionally verified by unauthenticated access"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "auth-bypass", "audit", "moderate"}
)
