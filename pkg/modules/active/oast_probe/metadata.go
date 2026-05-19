package oast_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oast-probe"
	ModuleName  = "OAST Probe"
	ModuleShort = "Detects blind vulnerabilities via out-of-band callbacks (DNS/HTTP)"
)

var (
	ModuleDesc = `## Description
Injects OAST (Out-of-Band Application Security Testing) callback URLs into HTTP headers
and URL-like parameters to detect blind vulnerabilities such as blind SSRF, blind XXE,
and blind command injection.

## Notes
- Requires an interactsh server (configured via oast settings)
- Injects unique callback URLs into headers: Referer, X-Forwarded-For, X-Forwarded-Host, Origin, X-Original-URL
- For insertion point scanning, targets parameters with URL-like values
- Findings arrive asynchronously via the polling callback — this module returns nil results directly
- DNS-only callbacks are reported as Info; HTTP callbacks are reported as High severity
- OWASP Top 10 2021: A10 (SSRF)

## References
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://portswigger.net/burp/documentation/collaborator`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssrf", "rce", "heavy"}
)
