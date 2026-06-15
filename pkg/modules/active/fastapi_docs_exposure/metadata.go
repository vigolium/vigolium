package fastapi_docs_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-docs-exposure"
	ModuleName  = "FastAPI Docs Exposure"
	ModuleShort = "Probes for exposed FastAPI interactive API documentation endpoints"
)

var (
	ModuleDesc = `**What it means:** FastAPI's interactive API docs are publicly reachable at the default Swagger UI (/docs), ReDoc (/redoc), or raw OpenAPI spec (/openapi.json), publishing a complete map of every route, method, schema, and parameter. Informational recon meant for internal developers.

**How it's exploited:** An attacker reads the docs to enumerate hidden, internal, or admin endpoints they would otherwise guess at, learning the exact parameters each expects, then targets authorization gaps, mass-assignment fields, and injectable parameters more efficiently.

**Fix:** Disable docs in production by setting docs_url, redoc_url, and openapi_url to None, or restrict these paths to authenticated internal users.`

	ModuleConfirmation = "Confirmed when documentation endpoints return 200 with expected FastAPI-specific markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "info-disclosure", "probe", "light"}
)
