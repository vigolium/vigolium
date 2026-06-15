package swagger_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "swagger-exposure"
	ModuleName  = "Exposed API Documentation"
	ModuleShort = "Detects publicly exposed Swagger/OpenAPI/Redoc documentation routes"

	ModuleDesc = `**What it means:** A Swagger/OpenAPI or Redoc documentation page, or a machine-readable OpenAPI/Swagger spec, is reachable at a common path without authentication. This publishes the full API attack surface - endpoints, parameters, request/response shapes, and the documented auth scheme.

**How it's exploited:** An attacker reads the docs to enumerate every route and its parameters, then targets privileged or accidentally-unauthenticated endpoints (admin, internal operations) with precise requests for authorization, injection, or business-logic testing - no guesswork needed.

**Fix:** Restrict the Swagger/OpenAPI UI and spec routes to authenticated or internal users, or disable them in production builds.`

	ModuleConfirmation = "A Swagger/OpenAPI documentation UI or specification document was reachable without authentication."
)

var (
	ModuleSeverity   = severity.Low
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "swagger", "openapi", "exposure", "info-leak", "light"}
)
