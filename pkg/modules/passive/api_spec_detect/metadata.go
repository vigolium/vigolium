package api_spec_detect

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-detect"
	ModuleName  = "API Spec Detect"
	ModuleShort = "Detects API spec responses and ingests endpoints for scanning"

	ModuleDesc = `**What it means:** A response served a machine-readable API specification (OpenAPI, Swagger, or Postman Collection). Informational discovery, not a vulnerability, but a publicly reachable spec maps the entire API - every route, method, parameter, and payload.

**How it's exploited:** An attacker treats the spec as a ready-made target list, enumerating documented endpoints (including admin or internal routes) and parameters, lowering the effort to find broken authorization or injection flaws. The scanner feeds the endpoints into its pipeline for testing.

**Fix:** Do not expose API spec or schema documents to unauthenticated users in production; restrict to internal networks or require auth.`

	ModuleConfirmation = "An API specification document was detected in a response body. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-detect", "light"}
)
