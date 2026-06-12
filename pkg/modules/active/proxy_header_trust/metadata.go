package proxy_header_trust

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-header-trust"
	ModuleName  = "Proxy Header Trust"
	ModuleShort = "Cross-framework detection of proxy header trust issues via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `**What it means:** The application trusts client-supplied proxy forwarding headers (X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-For) as if they came from a trusted reverse proxy. The scanner sends a GET to the site root with each header spoofed and observes a confirmed, reproducible behavioral change: the injected host reflected into a Location header or response body, a value-attributable redirect or status change for X-Forwarded-Proto, or a blocked-to-allowed access transition (or reproducible content variation) for a spoofed source IP.

**How it's exploited:** An attacker spoofs X-Forwarded-Host to poison absolute URLs the app generates, enabling password-reset link poisoning and web cache poisoning. Spoofing X-Forwarded-Proto can downgrade HTTPS enforcement or cookie security flags via redirect or status changes. Spoofing X-Forwarded-For with a trusted IP (for example 127.0.0.1) can bypass IP allowlists or rate limiting and reach IP-restricted content.

**Fix:** Do not trust forwarding headers from untrusted clients; have the edge proxy strip and re-set X-Forwarded-* and configure the app to honor them only from known proxy IPs.`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as host reflection, redirect differences, or access control bypass"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "moderate"}
)
