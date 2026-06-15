package wp_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-misconfig"
	ModuleName  = "WordPress Misconfiguration"
	ModuleShort = "Detects exposed WordPress configuration files, debug logs, and dangerous endpoints"
)

var (
	ModuleDesc = `**What it means:** A WordPress site exposes files and endpoints that should never be publicly reachable. Impact ranges from version disclosure to database credential exposure, so each finding carries its own severity (Info up to Critical).

**How it's exploited:** The worst cases are a readable wp-config.php (or backups like wp-config.php~, .old, .bak) and SQL dumps, handing an attacker DB credentials, auth salts, and the user table. Lesser findings are stepping stones: installer endpoints can reset the site and debug.log leaks paths.

**Fix:** Block web access to wp-config.php, backups, debug logs, SQL dumps, and installer/repair endpoints, and disable directory listing.`

	ModuleConfirmation = "Confirmed when probed WordPress files return 200 with expected content markers (PHP constants, log entries, directory index HTML)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
