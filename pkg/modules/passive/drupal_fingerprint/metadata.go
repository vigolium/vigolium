package drupal_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-drupal-fingerprint"
	ModuleName  = "Drupal Fingerprint"
	ModuleShort = "Identifies Drupal installations and detects core version, major generation (7/8/9/10/11), and contributed modules"
)

var (
	ModuleDesc = `## Description
Passively identifies Drupal installations from HTML responses and HTTP headers.
Detects core version generation (Drupal 7 vs 8+) via asset path patterns (/misc/ vs /core/),
X-Drupal-Cache and X-Drupal-Dynamic-Cache headers, generator meta tags, and drupalSettings
JavaScript objects. Enumerates contributed modules from asset URL paths.

## Notes
- Passive only: does not send any HTTP requests
- Detects Drupal via X-Drupal-Cache, X-Drupal-Dynamic-Cache headers
- Distinguishes Drupal 7 (/misc/, /sites/all/modules/) from Drupal 8+ (/core/, /modules/contrib/)
- Extracts contrib module names from asset URL paths
- Deduplicates by host

## References
- https://www.drupal.org/docs
- https://www.drupal.org/security`

	ModuleConfirmation = "Confirmed when Drupal-specific headers, asset paths, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"drupal", "cms", "fingerprint", "light"}
)
