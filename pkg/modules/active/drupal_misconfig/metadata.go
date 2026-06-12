package drupal_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-misconfig"
	ModuleName  = "Drupal Misconfiguration"
	ModuleShort = "Detects exposed Drupal configuration files, update scripts, installer, debug settings, and directory listings"
)

var (
	ModuleDesc = `**What it means:** A Drupal site is exposing files or endpoints that should be blocked from public access. Impact ranges from leaking database credentials and full site configuration (settings.php, config sync export) down to merely confirming the Drupal version (CHANGELOG.txt, README.txt). Each hit is reported at its own severity, from Critical for credential/installer/config exposure to Info for version banners.

**How it's exploited:** A readable settings.php leaks database credentials and the hash salt, a reachable install.php may allow re-installing the site under attacker control, and an exposed config sync directory leaks the full module and settings list. update.php and authorize.php can drive module/theme installation, a listable files directory exposes uploads and backups, and a leaked debug log reveals server paths and stack traces. Lower-severity version files let an attacker pinpoint the exact core version to target known CVEs.

**Fix:** Block web access to these admin scripts, config, source, and dotfiles, restrict the installer and update routes to authenticated admins, and disable directory listings.`

	ModuleConfirmation = "Confirmed when probed Drupal files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"drupal", "php", "misconfiguration", "info-disclosure", "moderate"}
)
