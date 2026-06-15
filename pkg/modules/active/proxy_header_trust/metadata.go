package proxy_header_trust

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-header-trust"
	ModuleName  = "Proxy Header Trust"
	ModuleShort = "Cross-framework detection of proxy header trust issues via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `**What it means:** The application trusts client-supplied proxy headers (X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-For) as if from a trusted reverse proxy. The scanner spoofs each and confirms a reproducible change: the injected host reflected into Location or body, an attributable redirect for X-Forwarded-Proto, or a blocked-to-allowed transition for a spoofed IP.

**How it's exploited:** Spoofing X-Forwarded-Host poisons generated URLs, enabling password-reset link and cache poisoning. X-Forwarded-Proto can downgrade HTTPS enforcement. X-Forwarded-For with 127.0.0.1 can bypass IP allowlists.

**Fix:** Have the edge proxy strip and re-set X-Forwarded-* and honor them only from known proxy IPs.`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as host reflection, redirect differences, or access control bypass"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "moderate"}
)
