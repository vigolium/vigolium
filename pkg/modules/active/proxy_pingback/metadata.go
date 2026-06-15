package proxy_pingback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-pingback"
	ModuleName  = "Proxy Pingback"
	ModuleShort = "Detects open proxy/callback endpoints via OAST URL injection into proxy-related paths"
)

var (
	ModuleDesc = `**What it means:** The server hosts an open proxy or callback endpoint that fetches a client-supplied URL, and it made an outbound request to a Vigolium-controlled OAST host the scanner injected. This is a confirmed Server-Side Request Forgery (SSRF) / open-proxy condition.

**How it's exploited:** An attacker swaps the OAST URL for an internal target to reach cloud metadata (169.254.169.254 to steal credentials), admin panels, or firewalled hosts, or relays attacks through the server.

**Fix:** Do not fetch arbitrary client-supplied URLs; if required, enforce a strict destination allowlist and block private ranges.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL via proxy endpoint"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"ssrf", "misconfiguration", "moderate"}
)
