package security_headers_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "security-headers-missing"
	ModuleName  = "Security Headers Missing"
	ModuleShort = "Detects missing/weak HTTP security headers and cacheable sensitive responses"
)

var (
	ModuleDesc = `**What it means:** An HTML response is missing or weakening HTTP security headers that browsers use to defend the page. This module passively flags absent X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, or Permissions-Policy headers, a weak Referrer-Policy (unsafe-url, no-referrer-when-downgrade), and sensitive HTTPS responses (set a cookie or render a password field) that lack a Cache-Control no-store/no-cache/private directive. These are hardening gaps, not active exploits, so the finding is informational.

**How it's exploited:** The missing headers remove browser protections that would otherwise blunt other attacks, so an attacker who already has a foothold (a reflected XSS payload, a phishing iframe, a network man-in-the-middle, or shared/proxy cache access) faces no extra obstacle: clickjacking, MIME-sniffing script execution, SSL stripping, referrer URL leakage, and caching of credentials or session cookies all become easier to pull off.

**Fix:** Send the recommended security headers (including HSTS, CSP, and X-Content-Type-Options nosniff), a strict Referrer-Policy, and Cache-Control: no-store on sensitive HTTPS pages.`

	ModuleConfirmation = "Confirmed when an HTTP response lacks recommended security headers, uses a weak Referrer-Policy, or serves cacheable sensitive content"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
