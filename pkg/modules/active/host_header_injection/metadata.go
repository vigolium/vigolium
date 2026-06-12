package host_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "host-header-injection"
	ModuleName  = "Host Header Injection"
	ModuleShort = "Detects host header injection and routing manipulation"
)

var (
	ModuleDesc = `**What it means:** The application trusts an attacker-controlled host value from the Host header or a forwarding header (X-Forwarded-Host, X-Host, X-Original-URL, Forwarded, X-Forwarded-Proto, X-Forwarded-Port, X-Real-IP, or Cf-Connecting-IP) and echoes it back into the response body or a response header. This module injected a sentinel host into each of those headers and observed it reflected, confirming the app uses the unvalidated value to build links, redirects, or other output rather than a fixed, trusted hostname.

**How it's exploited:** An attacker sends a request with a poisoned host header so the reflected value lands in a sensitive sink. If it reaches an absolute link or the Location header, this enables password-reset poisoning (reset emails point to the attacker's domain), open-redirect or web-cache poisoning, and in some setups server-side request forwarding to attacker-chosen back ends.

**Fix:** Derive hostnames from a server-side allowlist of trusted domains and ignore client-supplied Host and X-Forwarded-* headers when generating URLs, redirects, and emails.`

	ModuleConfirmation = "Confirmed when manipulated Host header value is reflected in response body, Location header, or other response headers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "misconfiguration", "moderate"}
)
