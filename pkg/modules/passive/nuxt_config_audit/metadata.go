package nuxt_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nuxt-config-audit"
	ModuleName  = "Nuxt Config Audit"
	ModuleShort = "Detects insecure Nuxt configuration patterns and sensitive data in Nuxt state"
)

var (
	ModuleDesc = `## Description
Scans response bodies for insecure Nuxt.js configuration patterns and sensitive data leaked
through Nuxt state blobs. Detects exposed __NUXT__ and __NUXT_DATA__ state in HTML, checks
for sensitive data patterns (API keys, tokens, internal URLs) within Nuxt state, and identifies
dangerous configuration options such as enabled devtools, exposed runtime secrets, production
source maps, and debug mode.

## Notes
- Passive only - does not send any HTTP requests
- Detects: __NUXT__ / __NUXT_DATA__ state blobs in HTML
- Scans Nuxt state for API keys, tokens, admin flags, internal IPs
- Checks config patterns: devtools, runtimeConfig secrets, productionSourceMap, debug
- Also detects /_nuxt/ source map exposure
- Deduplicates by host

## References
- https://nuxt.com/docs/guide/directory-structure/nuxt-config
- https://nuxt.com/docs/api/nuxt-config#runtimeconfig
- https://cwe.mitre.org/data/definitions/540.html
- https://cwe.mitre.org/data/definitions/200.html`

	ModuleConfirmation = "Confirmed when insecure configuration patterns or sensitive data are found in Nuxt state or config"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nuxt", "javascript", "misconfiguration", "light"}
)
