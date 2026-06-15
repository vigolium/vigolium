package security_headers_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "security-headers-missing"
	ModuleName  = "Security Headers Missing"
	ModuleShort = "Detects missing/weak HTTP security headers and cacheable sensitive responses"
)

var (
	ModuleDesc = `**What it means:** An HTML response is missing or weakening browser security headers: absent X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, or Permissions-Policy, a weak Referrer-Policy, or sensitive HTTPS pages lacking Cache-Control no-store. These are hardening gaps, so the finding is informational.

**How it's exploited:** The missing headers remove protections that blunt other attacks, so an attacker with a foothold (reflected XSS, a phishing iframe, a man-in-the-middle) finds clickjacking, MIME-sniffing, SSL stripping, referrer leakage, and caching of session cookies easier.

**Fix:** Send the recommended security headers (HSTS, CSP, X-Content-Type-Options nosniff), a strict Referrer-Policy, and Cache-Control no-store on sensitive HTTPS pages.`

	ModuleConfirmation = "Confirmed when an HTTP response lacks recommended security headers, uses a weak Referrer-Policy, or serves cacheable sensitive content"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
