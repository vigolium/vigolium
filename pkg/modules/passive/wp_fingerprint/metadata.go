package wp_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-fingerprint"
	ModuleName  = "WordPress Fingerprint"
	ModuleShort = "Identifies WordPress installations and enumerates core version, plugins, and themes"
)

var (
	ModuleDesc = `**What it means:** The target runs WordPress and discloses identifying details in its HTML and headers (/wp-content/, the wp-json Link header, X-Pingback, the generator meta tag). The check extracts the core version and a plugin/theme inventory. Informational recon, not a vulnerability.

**How it's exploited:** An attacker uses the exposed version and plugin/theme names to map the attack surface and look up version-specific CVEs for those components. Outdated plugins are a leading entry point for WordPress compromise.

**Fix:** Keep core, plugins, and themes patched, remove unused components, and suppress the generator meta tag and asset ?ver= version strings.`

	ModuleConfirmation = "Confirmed when WordPress-specific paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "fingerprint", "light"}
)
