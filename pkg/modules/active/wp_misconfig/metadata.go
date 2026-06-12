package wp_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-misconfig"
	ModuleName  = "WordPress Misconfiguration"
	ModuleShort = "Detects exposed WordPress configuration files, debug logs, and dangerous endpoints"
)

var (
	ModuleDesc = `**What it means:** A WordPress site is exposing files and endpoints that should never be publicly reachable. Depending on what is found, the impact ranges from informational version disclosure to full database credential exposure, so individual findings carry their own severity (from Info up to Critical).

**How it's exploited:** The most damaging cases are a readable wp-config.php (or its editor backups such as wp-config.php~, .old, .save, .swp, .txt, .bak) and exposed SQL dumps, which hand an attacker database credentials, secret auth salts, and potentially the entire user table. Other findings are stepping stones: an open installer or repair endpoint can let an attacker reset or corrupt the site, a readable debug.log leaks stack traces and filesystem paths, directory listings reveal uploaded files and plugin slugs, readme.html discloses the version while license.txt confirms the install, and a triggerable wp-cron.php can be hammered for denial of service.

**Fix:** Block direct web access to wp-config.php, backups, debug logs, SQL dumps, and installer/repair endpoints, disable directory listing, and serve wp-cron only internally.`

	ModuleConfirmation = "Confirmed when probed WordPress files return 200 with expected content markers (PHP constants, log entries, directory index HTML)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
