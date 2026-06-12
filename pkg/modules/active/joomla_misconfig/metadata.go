package joomla_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-misconfig"
	ModuleName  = "Joomla Misconfiguration"
	ModuleShort = "Detects exposed Joomla configuration backups, log/temp directories, backup archives, and debug settings"
)

var (
	ModuleDesc = `**What it means:** The Joomla site exposes files or directories that should never be web-reachable, such as configuration.php editor backups (.bak/.old/~), listable log/temp/backup directories, Akeeba backup archives, version manifests, the com_ajax endpoint, or composer metadata. Depending on the artifact this leaks anything from the exact core version to full database credentials and the Joomla secret key.

**How it's exploited:** A configuration.php backup or an Akeeba .jpa/.zip archive hands an attacker the database username, password, and the secret key used for password resets and session tokens, enabling direct database access or admin account takeover. Listable log and backup directories expose error traces, uploads, and full site dumps, while exposed manifests, composer.json/lock, and installed.json reveal the precise Joomla and dependency versions an attacker uses to select matching public exploits.

**Fix:** Remove the backups, archives, and editor temp files from the webroot, disable directory listing (autoindex), and block public access to configuration backups, log/temp directories, manifests, and composer metadata at the web server.`

	ModuleConfirmation = "Confirmed when probed Joomla files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "misconfiguration", "info-disclosure", "moderate"}
)
