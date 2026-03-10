package security_headers_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "security-headers-missing"
	ModuleName  = "Security Headers Missing"
	ModuleShort = "Detects missing HTTP security headers in responses"
)

var (
	ModuleDesc = `## Description
Passively detects missing HTTP security headers that protect against common web
attacks including XSS, clickjacking, MIME sniffing, and protocol downgrade.

## Notes
- Checks for X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, and Permissions-Policy
- Runs per-host to avoid duplicate findings
- Only flags HTML responses to reduce noise

## References
- https://owasp.org/www-project-secure-headers/
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when HTTP response lacks one or more recommended security headers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"header-security", "misconfiguration", "light"}
)
