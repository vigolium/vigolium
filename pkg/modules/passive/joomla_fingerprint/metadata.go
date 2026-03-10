package joomla_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-fingerprint"
	ModuleName  = "Joomla Fingerprint"
	ModuleShort = "Identifies Joomla installations and enumerates components, modules, and plugins from asset paths"
)

var (
	ModuleDesc = `## Description
Passively identifies Joomla installations from HTML responses. Detects Joomla
via generator meta tags, /administrator/ links, /media/com_* and /components/com_*
asset paths, and Joomla-specific JavaScript objects. Enumerates installed
extensions (components, modules, plugins) from URL patterns. Distinguishes
Joomla 4+ by /api/index.php references.

## Notes
- Passive only: does not send any HTTP requests
- Detects Joomla via generator meta tag, /media/system/js/ paths, com_* references
- Enumerates extensions from /components/com_*, /media/com_*, /modules/mod_* paths
- Detects Joomla 4+ via /api/index.php references
- Deduplicates by host

## References
- https://docs.joomla.org/
- https://developer.joomla.org/security-centre.html`

	ModuleConfirmation = "Confirmed when Joomla-specific asset paths, headers, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"joomla", "cms", "fingerprint", "light"}
)
