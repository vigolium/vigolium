package api_spec_ingest

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-ingest"
	ModuleName  = "API Spec Ingest"
	ModuleShort = "Discovers API specs (OpenAPI/Swagger/Postman) and ingests endpoints for scanning"

	ModuleDesc = `**What it means:** A publicly reachable API specification document (OpenAPI, Swagger, or a Postman collection) was found at a common path such as /openapi.json, /v3/api-docs, or /swagger.yaml. This is an informational discovery, not a vulnerability by itself, but the spec hands anyone a machine-readable blueprint of the API, including endpoints, parameters, and expected request shapes that are often otherwise undocumented.

**How it's exploited:** An attacker downloads the spec to map the full API attack surface in seconds, revealing hidden, internal, admin, or deprecated endpoints and their exact parameters. This module parses the spec and automatically feeds the extracted endpoints back into the scan so they get audited; for an external attacker the same blueprint dramatically lowers the effort to find and target authorization gaps, injection points, and exposed functionality.

**Fix:** Restrict access to API specification documents so they are not served to anonymous or untrusted clients, or remove them from production if they are not intended to be public.`

	ModuleConfirmation = "An API specification document was found and successfully parsed. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-ingest", "light"}
)
