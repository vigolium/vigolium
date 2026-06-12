package fastapi_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-fingerprint"
	ModuleName  = "FastAPI Fingerprint"
	ModuleShort = "Identifies FastAPI/Starlette/Uvicorn installations from response headers, body patterns, and endpoints"
)

var (
	ModuleDesc = `**What it means:** The target reveals it is built on the FastAPI/Starlette/Uvicorn Python stack. This is an informational technology fingerprint, not a vulnerability itself, but it leaks framework details that narrow down which attacks and known issues apply. It is reported only when at least two independent signals agree: a Server header naming Uvicorn, the FastAPI {"detail":...} error shape on 4xx/5xx responses, OpenAPI spec markers in the body, exposed /docs (Swagger UI) or /redoc documentation endpoints, or an x-process-time middleware header.
**How it's exploited:** An attacker uses this to map the attack surface and prioritize FastAPI/Starlette/Uvicorn-specific weaknesses, such as known CVEs in those packages, predictable error and validation behavior, and the interactive /docs or /redoc pages and the OpenAPI schema that enumerate every endpoint, parameter, and type for targeted probing.
**Fix:** Suppress framework-identifying headers (Server, x-process-time) at the proxy or middleware and disable or authenticate the /docs, /redoc, and OpenAPI schema endpoints in production.`

	ModuleConfirmation = "Confirmed when 2+ independent FastAPI/Starlette/Uvicorn-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fastapi", "python", "fingerprint", "light"}
)
