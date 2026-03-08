package cms_installer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-cms-installer-exposure"
	ModuleName  = "CMS Installer Exposure"
	ModuleShort = "Detects exposed CMS installation wizards for WordPress, Drupal, and Joomla"
)

var (
	ModuleDesc = `## Description
Probes for exposed CMS installation and setup wizards that should not be
accessible in production deployments. Covers WordPress, Drupal, and Joomla
installer endpoints. An accessible installer can allow an attacker to
re-install or reconfigure the CMS.

## Notes
- Runs once per host
- Checks WordPress /wp-admin/install.php, Drupal /install.php and /core/install.php, Joomla /installation/index.php
- Validates responses with CMS-specific content markers
- Fingerprints 404 to avoid false positives

## References
- https://developer.wordpress.org/advanced-administration/before-install/howto-install/
- https://www.drupal.org/docs/getting-started/installing-drupal
- https://docs.joomla.org/Installing_Joomla`

	ModuleConfirmation = "Confirmed when installer endpoints return 200 with installation wizard content markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "drupal", "joomla", "misconfiguration", "probe", "light"}
)
