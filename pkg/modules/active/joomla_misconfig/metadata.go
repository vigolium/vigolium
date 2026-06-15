package joomla_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-misconfig"
	ModuleName  = "Joomla Misconfiguration"
	ModuleShort = "Detects exposed Joomla configuration backups, log/temp directories, backup archives, and debug settings"
)

var (
	ModuleDesc = `**What it means:** The Joomla site exposes files that should never be web-reachable: configuration.php backups (.bak/.old/~), listable log/temp/backup directories, Akeeba archives, or composer metadata. This leaks anything from the core version to database credentials and the Joomla secret key.

**How it's exploited:** A configuration.php backup or Akeeba archive hands an attacker the database password and the secret key used for password resets and sessions, enabling database access or admin takeover. Listable directories expose uploads and site dumps.

**Fix:** Remove backups, archives, and temp files from the webroot, disable directory listing, and block public access at the web server.`

	ModuleConfirmation = "Confirmed when probed Joomla files return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "misconfiguration", "info-disclosure", "moderate"}
)
