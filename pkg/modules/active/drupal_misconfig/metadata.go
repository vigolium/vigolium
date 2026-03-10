package drupal_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-misconfig"
	ModuleName  = "Drupal Misconfiguration"
	ModuleShort = "Detects exposed Drupal configuration files, update scripts, installer, debug settings, and directory listings"
)

var (
	ModuleDesc = `## Description
Probes for Drupal-specific files and endpoints that should not be publicly
accessible: settings.php source disclosure, services.yml, update.php, install.php,
authorize.php, CHANGELOG.txt, config sync directory, Twig debug output, public
files directory listing, and development services.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Covers both Drupal 7 and Drupal 8+ paths
- Fingerprints 404 responses to detect custom error pages

## References
- https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-your-site
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Drupal files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"drupal", "php", "misconfiguration", "info-disclosure", "moderate"}
)
