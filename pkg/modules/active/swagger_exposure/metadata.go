package swagger_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "swagger-exposure"
	ModuleName  = "Exposed API Documentation"
	ModuleShort = "Detects publicly exposed Swagger/OpenAPI/Redoc documentation routes"

	ModuleDesc = `Probes common Swagger, OpenAPI and Redoc paths and reports when an
interactive API documentation UI or a machine-readable specification document is
reachable without authentication. Exposed API documentation discloses the full
API attack surface — endpoints, parameters, and authentication scheme — to
anonymous users. This module performs detection only; endpoint parsing and
ingestion into the scan is handled separately by the api-spec-ingest module.`

	ModuleConfirmation = "A Swagger/OpenAPI documentation UI or specification document was reachable without authentication."
)

var (
	ModuleSeverity   = severity.Low
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "swagger", "openapi", "exposure", "info-leak", "light"}
)
