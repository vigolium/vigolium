package wp_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-fingerprint"
	ModuleName  = "WordPress Fingerprint"
	ModuleShort = "Identifies WordPress installations and enumerates core version, plugins, and themes"
)

var (
	ModuleDesc = `**What it means:** The target is running WordPress, and the site discloses identifying details in its HTML and headers. This passive check fingerprints the install from signals like /wp-content/, /wp-includes/, the wp-json Link header, the X-Pingback header, and the generator meta tag, then extracts the core version and an inventory of plugin and theme slugs (with versions where assets carry a ?ver= query string). This is informational, not a vulnerability by itself, but the disclosed software inventory is valuable reconnaissance.

**How it's exploited:** An attacker uses the exposed WordPress version, plugin names, and plugin/theme versions to map the attack surface and look up version-specific known vulnerabilities (CVEs) for those exact components, allowing them to target documented exploits instead of blindly probing. Outdated or vulnerable plugins identified this way are a leading entry point for WordPress site compromise.

**Fix:** Keep WordPress core, plugins, and themes fully patched, remove unused components, and suppress version disclosure (the generator meta tag and asset ?ver= query strings) so the precise software inventory is not advertised.`

	ModuleConfirmation = "Confirmed when WordPress-specific paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "fingerprint", "light"}
)
