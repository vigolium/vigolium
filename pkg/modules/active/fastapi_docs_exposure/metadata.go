package fastapi_docs_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-docs-exposure"
	ModuleName  = "FastAPI Docs Exposure"
	ModuleShort = "Probes for exposed FastAPI interactive API documentation endpoints"
)

var (
	ModuleDesc = `## Description
Probes for exposed FastAPI interactive API documentation. FastAPI auto-generates
Swagger UI at /docs, ReDoc at /redoc, and the OpenAPI spec at /openapi.json by
default. These endpoints reveal all API routes, schemas, and parameters, increasing
the attack surface for further exploitation.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Reported as low severity (information disclosure)

## References
- https://fastapi.tiangolo.com/tutorial/metadata/`

	ModuleConfirmation = "Confirmed when documentation endpoints return 200 with expected FastAPI-specific markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "info-disclosure", "probe", "light"}
)
