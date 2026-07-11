package nuxt_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nuxt-config-audit"
	ModuleName  = "Nuxt Config Audit"
	ModuleShort = "Detects insecure Nuxt configuration patterns and sensitive data in Nuxt state"
)

var (
	ModuleDesc = `**What it means:** Nuxt client state or source contains security-relevant values and configuration. Routine role data, public identifiers, internal addresses, config flags, and source-map references are observations. Substantive private credentials in state are candidates.

**How it's exploited:** Anyone who loads the page reads the disclosed values. Leaked keys, tokens, or database URLs are reused against backends; internal IPs map the network; source maps reconstruct the original source.

**Fix:** Keep secrets in server-only runtimeConfig, never in public state; disable devtools, debug, and production source maps.`

	ModuleConfirmation = "Candidate for substantive private credentials in Nuxt state; config strings and source-map references remain observations until runtime access or sensitive content is verified"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nuxt", "javascript", "misconfiguration", "light"}
)
