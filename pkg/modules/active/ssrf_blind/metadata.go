package ssrf_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-blind"
	ModuleName  = "Blind SSRF Detection"
	ModuleShort = "Detects blind server-side request forgery via OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** A URL-like parameter (for example url, uri, redirect, callback, proxy, fetch) causes the server to make an outbound request to a destination the client controls, without echoing the fetched response back. This is a blind Server-Side Request Forgery (SSRF) flaw: the application can be coerced into acting as a proxy from inside its own network.

**How it's exploited:** This module confirmed the vulnerability by injecting an out-of-band (OAST) callback URL into the parameter and observing the server make a DNS or HTTP request back to that host. An attacker swaps the callback for internal targets to reach cloud metadata endpoints (such as 169.254.169.254 for credentials), internal admin panels, or other services unreachable from the outside, and to scan or pivot within the trusted network even though no response is returned to them.

**Fix:** Validate and allowlist outbound destinations, resolve and block requests to private/link-local/loopback ranges and cloud metadata IPs, and disable unneeded URL schemes and redirect following.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL injected into a URL-like parameter"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
