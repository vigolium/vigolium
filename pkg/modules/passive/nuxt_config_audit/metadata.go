package nuxt_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nuxt-config-audit"
	ModuleName  = "Nuxt Config Audit"
	ModuleShort = "Detects insecure Nuxt configuration patterns and sensitive data in Nuxt state"
)

var (
	ModuleDesc = `**What it means:** A Nuxt.js application is leaking sensitive data or insecure configuration into the page returned to the browser. This passive check inspects HTML and Nuxt JS/JSON responses and flags secrets in the embedded __NUXT__ / __NUXT_DATA__ state blob (API keys, access tokens, admin or role flags, internal private IPs, database connection strings, AWS keys), risky config flags (devtools enabled, runtimeConfig secrets exposed client-side, production source maps, debug mode), and references to /_nuxt/ source map files.

**How it's exploited:** Anyone who loads the page can read the disclosed values straight from the response. Leaked API keys, tokens, or database URLs can be reused directly against backend services; an exposed admin or role flag reveals account or logic details; internal IPs map the private network; and source maps reconstruct the original application source for deeper attack-surface analysis.

**Fix:** Keep secrets in server-only runtimeConfig, never in public state; disable devtools, debug, and production source maps in production builds.`

	ModuleConfirmation = "Confirmed when insecure configuration patterns or sensitive data are found in Nuxt state or config"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nuxt", "javascript", "misconfiguration", "light"}
)
