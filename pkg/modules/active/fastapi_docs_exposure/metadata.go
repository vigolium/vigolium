package fastapi_docs_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-docs-exposure"
	ModuleName  = "FastAPI Docs Exposure"
	ModuleShort = "Probes for exposed FastAPI interactive API documentation endpoints"
)

var (
	ModuleDesc = `**What it means:** The application leaves FastAPI's auto-generated interactive API documentation publicly reachable, at the default Swagger UI path (/docs), ReDoc path (/redoc), or the raw OpenAPI specification (/openapi.json). These endpoints publish a complete map of the API, including every route, HTTP method, request and response schema, parameter, and data model. This is an information-disclosure issue: it hands an attacker a precise blueprint of the application's attack surface that is normally meant for internal developers only.

**How it's exploited:** An attacker reads the exposed docs to enumerate hidden, internal, or administrative endpoints they would otherwise have to guess at, and learns the exact parameters and payload structures each one expects. That blueprint lets them target authorization gaps, mass-assignment fields, and injectable parameters far more efficiently, turning blind probing into focused attacks against the documented routes.

**Fix:** Disable the docs in production by setting docs_url, redoc_url, and openapi_url to None when creating the FastAPI app, or restrict these paths to authenticated internal users.`

	ModuleConfirmation = "Confirmed when documentation endpoints return 200 with expected FastAPI-specific markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "info-disclosure", "probe", "light"}
)
