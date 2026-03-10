package hsts_preload_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "hsts-preload-audit"
	ModuleName  = "HSTS Preload Audit"
	ModuleShort = "Audits Strict-Transport-Security header for preload readiness"
)

var (
	ModuleDesc = `## Description
Passively audits the Strict-Transport-Security (HSTS) header on HTTPS responses
to verify preload readiness: sufficient max-age, includeSubDomains directive,
and preload directive.

## Notes
- Only checks HTTPS HTML responses
- Requires max-age >= 31536000 (1 year) for preload eligibility
- Runs per-host to avoid duplicate findings

## References
- https://hstspreload.org/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security`

	ModuleConfirmation = "Confirmed when HSTS header is missing, incomplete, or not preload-ready"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"header-security", "cryptography", "light"}
)
