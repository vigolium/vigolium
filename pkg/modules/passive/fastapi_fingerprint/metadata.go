package fastapi_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-fingerprint"
	ModuleName  = "FastAPI Fingerprint"
	ModuleShort = "Identifies FastAPI/Starlette/Uvicorn installations from response headers, body patterns, and endpoints"
)

var (
	ModuleDesc = `**What it means:** The target runs the FastAPI/Starlette/Uvicorn Python stack. An informational fingerprint, reported only when two signals agree: a Uvicorn Server header, the FastAPI detail error shape, OpenAPI markers, exposed /docs or /redoc, or an x-process-time header.

**How it's exploited:** An attacker maps the attack surface and prioritizes stack-specific CVEs, using the interactive /docs and /redoc pages and the OpenAPI schema that enumerate every endpoint, parameter, and type for targeted probing.

**Fix:** Suppress identifying headers (Server, x-process-time) and disable or authenticate the /docs, /redoc, and OpenAPI schema endpoints in production.`

	ModuleConfirmation = "Confirmed when 2+ independent FastAPI/Starlette/Uvicorn-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fastapi", "python", "fingerprint", "light"}
)
