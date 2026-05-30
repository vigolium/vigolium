package csp_weakness_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csp-weakness-audit"
	ModuleName  = "CSP Weakness Audit"
	ModuleShort = "Detects weak or unsafe Content-Security-Policy directives"
)

var (
	ModuleDesc = `## Description
Parses Content-Security-Policy headers and evaluates individual directives for
unsafe configurations that reduce CSP effectiveness. Detects unsafe-inline,
unsafe-eval, wildcard sources, missing frame-ancestors, missing base-uri
restriction, overly permissive script-src, and data: or blob: URI schemes
in sensitive directives.

## Notes
- Passive only - does not send any HTTP requests
- Only processes HTML responses (text/html content type)
- Parses actual CSP header values, not just presence/absence
- Each weakness emits a separate finding with the problematic directive
- Deduplicates by host
- Complements security_headers_missing which only checks for header presence

## References
- https://cwe.mitre.org/data/definitions/693.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- https://csp-evaluator.withgoogle.com/`

	ModuleConfirmation = "Confirmed when CSP header contains directives that significantly weaken its protection"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"header-security", "misconfiguration", "xss", "light"}
)
