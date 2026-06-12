package drupal_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-fingerprint"
	ModuleName  = "Drupal Fingerprint"
	ModuleShort = "Identifies Drupal installations and detects core version, major generation (7/8/9/10/11), and contributed modules"
)

var (
	ModuleDesc = `**What it means:** The target is running the Drupal CMS, identified passively from response signals such as X-Drupal-Cache and X-Drupal-Dynamic-Cache headers, a Drupal generator meta tag, the drupalSettings JavaScript object, and core asset paths. The module also infers the major generation (Drupal 7 versus 8+) from asset path patterns and lists contributed module names found in asset URLs. This is informational technology disclosure, not a vulnerability in itself, but it narrows the attack surface an attacker has to consider.

**How it's exploited:** Knowing the platform is Drupal, its generation, and which contrib modules are installed lets an attacker map the attack surface and target version-specific or module-specific public exploits and known CVEs (for example Drupalgeddon-class core flaws or vulnerable contrib modules) instead of probing blindly. Combined with a precise core version it enables direct selection of matching exploit code.

**Fix:** Suppress version and platform disclosure by removing the generator meta tag and X-Generator header, and keep Drupal core and all contributed modules patched to current secure releases.`

	ModuleConfirmation = "Confirmed when Drupal-specific headers, asset paths, or meta tags are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "cms", "fingerprint", "light"}
)
