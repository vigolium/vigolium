package fastapi_auth_inconsistency

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-auth-inconsistency"
	ModuleName  = "FastAPI Auth Inconsistency"
	ModuleShort = "Fetches OpenAPI schema and finds unprotected operations"
)

var (
	ModuleDesc = `**What it means:** FastAPI's OpenAPI security contract and runtime behavior differ. Missing metadata is an observation because middleware or in-function checks may apply. A finding requires a declared-protected operation to return stable, substantive data to a credential-free client.

**How it's exploited:** An attacker enumerates the schema and calls an operation without the token, cookie, or API key its contract requires.

**Fix:** Apply consistent authentication dependencies and remove unintended security: [] overrides.`

	ModuleConfirmation = "Confirmed only when an operation declared protected returns repeated, stable, substantive JSON to a fresh credential-free requester; missing security metadata and 422 responses are not bypass evidence"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "auth-bypass", "audit", "moderate"}
)
