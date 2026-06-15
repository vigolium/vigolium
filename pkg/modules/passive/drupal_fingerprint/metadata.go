package drupal_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-fingerprint"
	ModuleName  = "Drupal Fingerprint"
	ModuleShort = "Identifies Drupal installations and detects core version, major generation (7/8/9/10/11), and contributed modules"
)

var (
	ModuleDesc = `**What it means:** The target runs Drupal, identified passively from X-Drupal-Cache headers, the generator meta tag, the drupalSettings object, and core asset paths. The check also infers the major generation (Drupal 7 versus 8+) and lists contributed modules. Informational technology disclosure, not a vulnerability itself.

**How it's exploited:** An attacker uses the platform, generation, and module names to target version- and module-specific exploits and known CVEs (such as Drupalgeddon-class core flaws) instead of probing blindly.

**Fix:** Remove the generator meta tag and X-Generator header, and keep Drupal core and contributed modules patched to current secure releases.`

	ModuleConfirmation = "Confirmed when Drupal-specific headers, asset paths, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "cms", "fingerprint", "light"}
)
