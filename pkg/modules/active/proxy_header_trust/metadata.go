package proxy_header_trust

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-header-trust"
	ModuleName  = "Proxy Header Trust"
	ModuleShort = "Cross-framework detection of proxy header trust issues via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `## Description
Cross-framework detection of proxy header trust issues. Tests whether the application
blindly trusts X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-For headers,
which can lead to host injection, protocol confusion, and IP-based access control bypass.

## Notes
- Runs once per host
- Sends baseline request then compares with header-injected variants
- X-Forwarded-Host reflected in Location or body indicates host injection (High)
- X-Forwarded-Proto behavior changes indicate protocol confusion (Medium)
- X-Forwarded-For bypassing restrictions indicates IP trust issues (High)
- CF-21, FA-05, FL-06, DJ-08: cross-framework proxy header trust detection

## References
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as host reflection, redirect differences, or access control bypass"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"misconfiguration", "header-security", "moderate"}
)
