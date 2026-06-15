package api_version_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-version-detect"
	ModuleName  = "API Version Detect"
	ModuleShort = "Detects API versioning patterns in URLs, headers, and response bodies"
)

var (
	ModuleDesc = `**What it means:** The application exposes its API version through a URL path (/v1/, /api/v2/), a header (API-Version, X-API-Version, Accept-Version), or a JSON body field. Informational fingerprint, not a vulnerability on its own.

**How it's exploited:** An attacker uses the disclosed version to map the API surface, look up version-specific known issues, and probe for older or deprecated versions (/v1/ alongside /v2/) that may still be reachable but lack newer authorization or validation fixes.

**Fix:** Fully decommission deprecated API versions rather than leaving them accessible, and apply consistent authentication and authorization across every supported version.`

	ModuleConfirmation = "Confirmed when URL path, headers, or response body contain API version indicators"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"api", "fingerprint", "light"}
)
