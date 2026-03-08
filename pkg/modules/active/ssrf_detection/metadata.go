package ssrf_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-ssrf-detection"
	ModuleName  = "SSRF Detection"
	ModuleShort = "Detects server-side request forgery via out-of-band and in-band techniques"
)

var (
	ModuleDesc = `## Description
Detects Server-Side Request Forgery (SSRF) vulnerabilities by injecting internal and
external URLs into parameters and analyzing response differences and timing.

## Notes
- Tests for in-band SSRF using internal IP addresses and cloud metadata endpoints
- Analyzes response differences between original and injected values
- Targets parameters with URL-like values
- OWASP Top 10 2021: A10

## References
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://portswigger.net/web-security/ssrf`

	ModuleConfirmation = "Confirmed when injected internal URLs or metadata endpoints cause different response content or timing compared to baseline"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"ssrf", "injection", "moderate"}
)
