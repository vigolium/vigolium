package fastapi_docs_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastapi-docs-exposure"
	ModuleName  = "FastAPI Docs Exposure"
	ModuleShort = "Probes for exposed FastAPI interactive API documentation endpoints"
)

var (
	ModuleDesc = `**What it means:** An isolated credential-free request reached a Swagger UI, ReDoc loader, or structurally valid OpenAPI document at a FastAPI-default path. The path does not by itself prove the framework.

**How it's exploited:** Attackers can use documented routes and schemas for reconnaissance. Documentation reachability alone does not prove that any route is sensitive, undocumented, or missing authorization, so this remains an observation.

**Fix:** Disable docs in production by setting docs_url, redoc_url, and openapi_url to None, or restrict these paths to authenticated internal users.`

	ModuleConfirmation = "Observed when credential-free 200 responses pass grouped UI markers or structural spec parsing plus soft-404 and catch-all controls"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"fastapi", "python", "info-disclosure", "probe", "light"}
)
