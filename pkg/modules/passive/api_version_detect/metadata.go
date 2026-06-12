package api_version_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-version-detect"
	ModuleName  = "API Version Detect"
	ModuleShort = "Detects API versioning patterns in URLs, headers, and response bodies"
)

var (
	ModuleDesc = `**What it means:** The application exposes its API version through a URL path segment (such as /v1/ or /api/v2/), a version response header (API-Version, X-API-Version, Accept-Version), or a version field in a JSON response body. This is an informational fingerprint, not a vulnerability on its own, but it reveals the API surface and which version is in use.

**How it's exploited:** An attacker uses the disclosed version to map the API attack surface and look up version-specific known issues, then probes for older or deprecated versions (for example /v1/ alongside /v2/) that may still be reachable but lack newer authorization or input-validation fixes, broadening the testable endpoint set.

**Fix:** Treat the version indicator as expected API metadata; ensure deprecated or legacy API versions are fully decommissioned rather than left accessible, and apply consistent authentication and authorization controls across every supported version.`

	ModuleConfirmation = "Confirmed when URL path, headers, or response body contain API version indicators"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"api", "fingerprint", "light"}
)
