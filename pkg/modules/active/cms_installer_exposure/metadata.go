package cms_installer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cms-installer-exposure"
	ModuleName  = "CMS Installer Exposure"
	ModuleShort = "Detects exposed CMS installation wizards for WordPress, Drupal, and Joomla"
)

var (
	ModuleDesc = `**What it means:** The CMS installation or setup wizard (WordPress, Drupal 7 or 8+, or Joomla) is reachable on a live, production host instead of being removed or locked down after install. An exposed installer is a critical misconfiguration because it lets anyone walk through the setup flow against a running site.

**How it's exploited:** An attacker who reaches the installer can re-run setup to point the CMS at a database they control, reset or hijack the admin account, and reconfigure the site, leading to full takeover of the application and any data it manages. The wizard also leaks framework, version, and configuration details useful for further attacks.

**Fix:** Delete or block access to the installer endpoints (such as /wp-admin/install.php, /install.php, /core/install.php, /installation/index.php) once setup is complete, and restrict them by IP or auth if they must remain.`

	ModuleConfirmation = "Confirmed when installer endpoints return 200 with installation wizard content markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "drupal", "joomla", "misconfiguration", "probe", "light"}
)
