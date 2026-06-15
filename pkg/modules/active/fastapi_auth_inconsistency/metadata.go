package fastapi_auth_inconsistency

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-auth-inconsistency"
	ModuleName  = "FastAPI Auth Inconsistency"
	ModuleShort = "Fetches OpenAPI schema and finds unprotected operations"
)

var (
	ModuleDesc = `**What it means:** This FastAPI service publishes its OpenAPI schema at /openapi.json, and one or more operations under /api declare no authentication - opting out of global security (security: []) or defining none - so they are reachable without credentials.

**How it's exploited:** An attacker reads the public schema to enumerate the unprotected operations, then calls them with no token, cookie, or API key, so read/write actions meant for authenticated users can be done by anyone.

**Fix:** Apply a consistent auth dependency (global security or a per-route dependency) to every operation and remove any unintended security: [] overrides.`

	ModuleConfirmation = "Confirmed when OpenAPI spec reveals operations without security requirements, optionally verified by unauthenticated access"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "auth-bypass", "audit", "moderate"}
)
