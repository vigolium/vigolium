package wp_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-fingerprint"
	ModuleName  = "WordPress Fingerprint"
	ModuleShort = "Identifies WordPress installations and enumerates core version, plugins, and themes"
)

var (
	ModuleDesc = `## Description
Passively identifies WordPress installations from HTML responses, extracts core
version information, and builds an inventory of installed plugins and themes by
parsing asset URLs (/wp-content/plugins/<slug>/, /wp-content/themes/<slug>/).

## Notes
- Passive only: does not send any HTTP requests
- Detects WordPress via /wp-content/, /wp-includes/, wp-json, X-Pingback header, generator meta tag
- Extracts version from generator meta tag and RSS feed generator element
- Enumerates plugin/theme slugs from asset URL paths
- Deduplicates by host to avoid redundant processing

## References
- https://developer.wordpress.org/
- https://codex.wordpress.org/Determining_Plugin_and_Theme_License_Status`

	ModuleConfirmation = "Confirmed when WordPress-specific paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"wordpress", "cms", "php", "fingerprint", "light"}
)
