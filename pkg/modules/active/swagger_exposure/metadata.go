package swagger_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "swagger-exposure"
	ModuleName  = "Exposed API Documentation"
	ModuleShort = "Detects publicly exposed Swagger/OpenAPI/Redoc documentation routes"

	ModuleDesc = `**What it means:** An isolated credential-free request reached a structurally valid OpenAPI/Swagger document or a documentation loader confirmed by multiple product-specific markers and negative path controls.

**How it's exploited:** Attackers can use documented routes and schemas for reconnaissance. Documentation reachability alone does not prove that a route is sensitive, unintentionally public, or missing authorization, so the result remains an observation.

**Fix:** Restrict the Swagger/OpenAPI UI and spec routes to authenticated or internal users, or disable them in production builds.`

	ModuleConfirmation = "Observed when credential-free 200 responses pass structural spec parsing or complete UI-loader marker groups plus catch-all/reflection controls"
)

var (
	ModuleSeverity   = severity.Low
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "swagger", "openapi", "exposure", "info-leak", "light"}
)
