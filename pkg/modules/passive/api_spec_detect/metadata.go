package api_spec_detect

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-detect"
	ModuleName  = "API Spec Detect"
	ModuleShort = "Detects API spec responses and ingests endpoints for scanning"

	ModuleDesc = `Passively analyzes HTTP responses for API specification content (OpenAPI, Swagger,
Postman Collections). When a spec is detected, it is parsed and the extracted endpoints
are fed back into the scanning pipeline as new work items.`

	ModuleConfirmation = "An API specification document was detected in a response body. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-detect", "light"}
)
