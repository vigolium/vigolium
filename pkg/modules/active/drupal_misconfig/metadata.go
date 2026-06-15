package drupal_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-misconfig"
	ModuleName  = "Drupal Misconfiguration"
	ModuleShort = "Detects exposed Drupal configuration files, update scripts, installer, debug settings, and directory listings"
)

var (
	ModuleDesc = `**What it means:** A Drupal site exposes files or endpoints that should be blocked from public access, from leaking database credentials and full configuration (settings.php, config sync export) down to confirming the version (CHANGELOG.txt). Each hit is reported at its own severity.

**How it's exploited:** A readable settings.php leaks database credentials and the hash salt, install.php may allow re-installing under attacker control, and a config sync directory leaks the module list. update.php and authorize.php drive module installation; version files pinpoint the version for CVEs.

**Fix:** Block web access to these admin scripts, config, source, and dotfiles, and disable directory listings.`

	ModuleConfirmation = "Confirmed when probed Drupal files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"drupal", "php", "misconfiguration", "info-disclosure", "moderate"}
)
