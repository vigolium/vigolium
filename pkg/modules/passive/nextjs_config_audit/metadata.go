package nextjs_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-config-audit"
	ModuleName  = "Next.js Config Audit"
	ModuleShort = "Detects insecure Next.js configuration patterns"
)

var (
	ModuleDesc = `## Description
Scans response bodies for insecure Next.js configuration patterns that can introduce
security vulnerabilities. Checks for dangerous SVG allowances (XSS risk), wildcard
image domains (SSRF risk), HTTP protocol in image config (cleartext transport),
exposed production source maps (information disclosure), internal API exposure via
rewrites/redirects, and missing security headers configuration.

## Notes
- Passive only - does not send any HTTP requests
- Detects: dangerouslyAllowSVG, wildcard image hostnames, HTTP protocol, production source maps
- Also checks for internal API route exposure and missing security headers config
- Each matched pattern emits a separate finding with matched snippet
- Deduplicates by host

## References
- https://nextjs.org/docs/app/api-reference/next-config-js
- https://cwe.mitre.org/data/definitions/79.html
- https://cwe.mitre.org/data/definitions/918.html
- https://cwe.mitre.org/data/definitions/540.html`

	ModuleConfirmation = "Confirmed when insecure configuration patterns are found in Next.js config files"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
