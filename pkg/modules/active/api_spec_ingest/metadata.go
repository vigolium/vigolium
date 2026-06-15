package api_spec_ingest

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-ingest"
	ModuleName  = "API Spec Ingest"
	ModuleShort = "Discovers API specs (OpenAPI/Swagger/Postman) and ingests endpoints for scanning"

	ModuleDesc = `**What it means:** A publicly reachable API specification (OpenAPI, Swagger, or Postman collection) was found at a common path such as /openapi.json, /v3/api-docs, or /swagger.yaml. Informational discovery, but it hands anyone a machine-readable blueprint of endpoints and parameters.

**How it's exploited:** An attacker downloads the spec to map the full API attack surface in seconds, revealing hidden, internal, admin, or deprecated endpoints and their parameters. This module feeds the extracted endpoints back into the scan.

**Fix:** Restrict API specification documents so they are not served to anonymous clients, or remove them from production if not public.`

	ModuleConfirmation = "An API specification document was found and successfully parsed. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-ingest", "light"}
)
