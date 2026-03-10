package laravel_ignition_rce

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-ignition-rce"
	ModuleName  = "Laravel Ignition RCE"
	ModuleShort = "Detects exposed Ignition endpoints and flags CVE-2021-3129 RCE candidates"
)

var (
	ModuleDesc = `## Description
Probes for exposed Laravel Ignition debug endpoints (/_ignition/health-check,
/_ignition/execute-solution, /_ignition/scripts/*, /_ignition/styles/*) and
flags potential CVE-2021-3129 RCE candidates when version evidence indicates
facade/ignition < 2.5.2 or Laravel < 8.4.2.

## Notes
- Runs once per host to avoid redundant probing
- Does NOT attempt exploitation; reports as candidate with prerequisites
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages

## References
- https://nvd.nist.gov/vuln/detail/CVE-2021-3129
- https://www.ambionics.io/blog/laravel-debug-rce
- https://flareapp.io/docs/ignition-for-laravel/introduction`

	ModuleConfirmation = "Confirmed when Ignition endpoints are reachable and return expected framework-specific markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "rce", "light"}
)
