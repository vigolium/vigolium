package proxy_pingback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-pingback"
	ModuleName  = "Proxy Pingback"
	ModuleShort = "Detects open proxy/callback endpoints via OAST URL injection into proxy-related paths"
)

var (
	ModuleDesc = `## Description
Probes for open proxy and callback endpoints by injecting OAST callback URLs into common
proxy-related URL paths. This detects endpoints that forward or fetch user-supplied URLs
(open proxy / blind SSRF).

## Notes
- Requires an interactsh server (configured via oast settings)
- Targets proxy-related paths: /proxy, /httpproxy, /callback, /url, /remote, etc.
- Appends OAST URLs via query parameters: url, src, proxy, callback, email, etc.
- Sends 54 probe requests per host covering path and parameter patterns
- Each host is tested only once (DiskSet dedup)
- Findings arrive asynchronously via the OAST polling callback
- OWASP Top 10 2021: A10 (SSRF)

## References
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://portswigger.net/burp/documentation/collaborator`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL via proxy endpoint"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"ssrf", "misconfiguration", "moderate"}
)
