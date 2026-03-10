package ssrf_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-blind"
	ModuleName  = "Blind SSRF Detection"
	ModuleShort = "Detects blind server-side request forgery via OAST callbacks"
)

var (
	ModuleDesc = `## Description
Detects blind Server-Side Request Forgery (SSRF) vulnerabilities by injecting OAST callback
URLs into URL-like parameters. Unlike in-band SSRF detection, this module detects cases where
the server fetches the URL but does not reflect the response content back to the client.

## Notes
- Requires an interactsh server (configured via oast settings)
- Targets parameters whose name or value suggests URL input
- Injects multiple payload formats: direct HTTP/HTTPS, with path, with port, URL-encoded
- Findings arrive asynchronously via the OAST polling callback
- Deduplication via RHM and DiskSet to avoid redundant requests
- OWASP Top 10 2021: A10 (SSRF)

## References
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://portswigger.net/web-security/ssrf/blind`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL injected into a URL-like parameter"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"ssrf", "injection", "heavy"}
)
