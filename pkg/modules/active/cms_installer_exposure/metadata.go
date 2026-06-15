package cms_installer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cms-installer-exposure"
	ModuleName  = "CMS Installer Exposure"
	ModuleShort = "Detects exposed CMS installation wizards for WordPress, Drupal, and Joomla"
)

var (
	ModuleDesc = `**What it means:** The CMS installation wizard (WordPress, Drupal 7/8+, or Joomla) is reachable on a live production host instead of being removed after install - a critical misconfiguration, since anyone can run setup against a live site.

**How it's exploited:** An attacker who reaches the installer re-runs setup to point the CMS at a database they control, hijacks the admin account, and reconfigures the site, leading to full takeover. It also leaks version details.

**Fix:** Delete or block the installer endpoints (such as /wp-admin/install.php, /install.php, /core/install.php, /installation/index.php) once setup is done, and restrict by IP or auth if needed.`

	ModuleConfirmation = "Confirmed when installer endpoints return 200 with installation wizard content markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "drupal", "joomla", "misconfiguration", "probe", "light"}
)
