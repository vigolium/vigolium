package referrer_policy_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "referrer-policy-detect"
	ModuleName  = "Referrer Policy Detect"
	ModuleShort = "Detects missing or weak Referrer-Policy headers"
)

var (
	ModuleDesc = `## Description
Passively detects missing or weak Referrer-Policy headers that may leak
sensitive URL information to third-party origins.

## Notes
- Flags missing Referrer-Policy header
- Flags weak values: unsafe-url, no-referrer-when-downgrade
- Safe values are not flagged: no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin
- Runs per-host to avoid duplicate findings

## References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
- https://owasp.org/www-project-secure-headers/`

	ModuleConfirmation = "Confirmed when Referrer-Policy header is missing or set to a weak value"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"header-security", "misconfiguration", "light"}
)
