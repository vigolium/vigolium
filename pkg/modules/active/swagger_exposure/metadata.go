package swagger_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "swagger-exposure"
	ModuleName  = "Exposed API Documentation"
	ModuleShort = "Detects publicly exposed Swagger/OpenAPI/Redoc documentation routes"

	ModuleDesc = `**What it means:** A Swagger/OpenAPI or Redoc API documentation page, or a machine-readable OpenAPI/Swagger specification document, is reachable at a common path without authentication. This publishes the application's full API attack surface to anyone, including endpoints, parameters, request and response shapes, and the documented authentication scheme.

**How it's exploited:** An attacker reads the exposed documentation to enumerate every API route and its required parameters, then targets undocumented-from-the-UI or privileged endpoints (admin, internal, or unauthenticated-by-mistake operations) and crafts precise requests for authorization, injection, or business-logic testing without any guesswork. The spec effectively hands them a complete map of where to probe next.

**Fix:** Restrict the Swagger/OpenAPI UI and specification routes to authenticated or internal users, or disable them in production builds.`

	ModuleConfirmation = "A Swagger/OpenAPI documentation UI or specification document was reachable without authentication."
)

var (
	ModuleSeverity   = severity.Low
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "swagger", "openapi", "exposure", "info-leak", "light"}
)
