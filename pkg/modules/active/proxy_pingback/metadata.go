package proxy_pingback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-pingback"
	ModuleName  = "Proxy Pingback"
	ModuleShort = "Detects open proxy/callback endpoints via OAST URL injection into proxy-related paths"
)

var (
	ModuleDesc = `**What it means:** The server hosts an open proxy or callback endpoint that fetches a URL supplied by the client, and it made an outbound request to a Vigolium-controlled OAST callback host that the attacker injected. This is a confirmed Server-Side Request Forgery (SSRF) / open-proxy condition: the server can be coerced into making arbitrary requests on the attacker's behalf.
**How it's exploited:** An attacker swaps the OAST URL for an internal target to reach cloud metadata services (for example the 169.254.169.254 endpoint to steal credentials), internal admin panels, or other hosts behind the firewall, or uses the server as an anonymizing relay to attack third parties from its IP. Because the out-of-band callback fired, the SSRF is proven rather than merely suspected.
**Fix:** Do not fetch arbitrary client-supplied URLs; if a proxy/callback feature is required, enforce a strict allowlist of permitted destinations, block private and link-local IP ranges and redirects, and disable any unintended open-proxy behavior.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL via proxy endpoint"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"ssrf", "misconfiguration", "moderate"}
)
