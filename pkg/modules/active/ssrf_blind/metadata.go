package ssrf_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-blind"
	ModuleName  = "Blind SSRF Detection"
	ModuleShort = "Detects blind server-side request forgery via OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** A URL-like parameter (url, uri, redirect, proxy, fetch) makes the server send an outbound request to a client-controlled destination without echoing the response back. This is blind Server-Side Request Forgery (SSRF).

**How it's exploited:** Confirmed by injecting an out-of-band (OAST) callback URL and seeing the server make a DNS or HTTP request to it. An attacker swaps the callback for internal targets - cloud metadata (169.254.169.254), admin panels, internal services - to scan or pivot.

**Fix:** Allowlist outbound destinations, block private/link-local/loopback ranges and metadata IPs, and disable unneeded schemes and redirect following.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL injected into a URL-like parameter"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
