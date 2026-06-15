package nuxt_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nuxt-config-audit"
	ModuleName  = "Nuxt Config Audit"
	ModuleShort = "Detects insecure Nuxt configuration patterns and sensitive data in Nuxt state"
)

var (
	ModuleDesc = `**What it means:** A Nuxt.js app leaks sensitive data or insecure config into the page. This passive check flags secrets in the embedded __NUXT__ / __NUXT_DATA__ state (API keys, tokens, admin/role flags, internal IPs, database strings, AWS keys), risky config (devtools, client-exposed runtimeConfig secrets, source maps, debug mode).

**How it's exploited:** Anyone who loads the page reads the disclosed values. Leaked keys, tokens, or database URLs are reused against backends; internal IPs map the network; source maps reconstruct the original source.

**Fix:** Keep secrets in server-only runtimeConfig, never in public state; disable devtools, debug, and production source maps.`

	ModuleConfirmation = "Confirmed when insecure configuration patterns or sensitive data are found in Nuxt state or config"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nuxt", "javascript", "misconfiguration", "light"}
)
