package api_spec_detect

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "api-spec-detect"
	ModuleName  = "API Spec Detect"
	ModuleShort = "Detects API spec responses and ingests endpoints for scanning"

	ModuleDesc = `**What it means:** A response served a machine-readable API specification document (OpenAPI, Swagger, or a Postman Collection). This is an informational discovery finding, not a vulnerability on its own, but a publicly reachable spec hands out a complete, authoritative map of the application's API: every route, HTTP method, parameter, and expected payload.

**How it's exploited:** An attacker treats the exposed spec as a ready-made target list, enumerating every documented endpoint, including admin, internal, or undocumented-elsewhere routes, and the exact parameters each expects, which dramatically lowers the effort to find broken authorization, injection, or business-logic flaws. The scanner itself parses the spec and feeds the discovered endpoints back into its own pipeline so they get actively tested.

**Fix:** Do not expose API specification or schema documents to unauthenticated users in production; restrict them to internal networks or require authentication, and avoid documenting sensitive internal routes in any publicly reachable spec.`

	ModuleConfirmation = "An API specification document was detected in a response body. " +
		"Extracted endpoints have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"api", "discovery", "spec-detect", "light"}
)
