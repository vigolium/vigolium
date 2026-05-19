package api_spec_ingest

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-ingest"
	ModuleName  = "API Spec Ingest"
	ModuleShort = "Discovers API specs (OpenAPI/Swagger/Postman) and ingests endpoints for scanning"

	ModuleDesc = `Probes common paths for API specification files (OpenAPI, Swagger, Postman Collections),
parses discovered specs, and feeds the extracted endpoints back into the scanning pipeline
as new work items. This extends attack surface coverage by automatically discovering and
auditing API endpoints defined in specification documents.`

	ModuleConfirmation = "An API specification document was found and successfully parsed. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-ingest", "light"}
)
