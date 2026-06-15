package host_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "host-header-injection"
	ModuleName  = "Host Header Injection"
	ModuleShort = "Detects host header injection and routing manipulation"
)

var (
	ModuleDesc = `**What it means:** The application trusts an attacker-controlled value from the Host header or a forwarding header (X-Forwarded-Host, X-Original-URL, X-Forwarded-Proto, and similar) and echoes it into the response, using the unvalidated value rather than a fixed hostname.

**How it's exploited:** An attacker poisons the host header so the reflected value reaches a sensitive sink. In an absolute link or the Location header this enables password-reset poisoning (reset emails point to the attacker's domain), open-redirect, and web-cache poisoning.

**Fix:** Derive hostnames from a server-side allowlist and ignore client-supplied Host and X-Forwarded-* headers when building URLs, redirects, and emails.`

	ModuleConfirmation = "Confirmed when manipulated Host header value is reflected in response body, Location header, or other response headers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "misconfiguration", "moderate"}
)
