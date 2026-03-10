package info_disclosure_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "info-disclosure-detect"
	ModuleName  = "Info Disclosure Detect"
	ModuleShort = "Detects information disclosure patterns in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects information disclosure in HTTP responses including server version
strings, framework identifiers, internal IP addresses, and stack traces.

## Notes
- Scans response headers and bodies for disclosure patterns
- Detects server software versions, internal paths, email addresses, and debug info
- Runs per-request to catch endpoint-specific disclosures

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/`

	ModuleConfirmation = "Confirmed when response contains identifiable server versions, internal IPs, stack traces, or debug information"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"info-disclosure", "light"}
)
