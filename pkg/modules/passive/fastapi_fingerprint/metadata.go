package fastapi_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-fingerprint"
	ModuleName  = "FastAPI Fingerprint"
	ModuleShort = "Identifies FastAPI/Starlette/Uvicorn installations from response headers, body patterns, and endpoints"
)

var (
	ModuleDesc = `## Description
Passively identifies FastAPI/Starlette/Uvicorn installations by analyzing HTTP
response headers (Server, x-process-time), body patterns (OpenAPI JSON shape,
detail error shape), and well-known documentation endpoints (/docs, /redoc).
Requires 2+ independent signals to avoid false positives.

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host to avoid redundant processing
- Detects Uvicorn via Server header
- Recognizes FastAPI default error shape and OpenAPI spec indicators
- Identifies /docs (Swagger UI) and /redoc documentation endpoints

## References
- https://fastapi.tiangolo.com/`

	ModuleConfirmation = "Confirmed when 2+ independent FastAPI/Starlette/Uvicorn-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"fastapi", "python", "fingerprint", "light"}
)
