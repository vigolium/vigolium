package magento_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "magento-misconfig"
	ModuleName  = "Magento Misconfiguration"
	ModuleShort = "Detects exposed Magento setup wizard, downloader, version files, and admin panels"
)

var (
	ModuleDesc = `**What it means:** A Magento or Adobe Commerce store exposes files or interfaces that should never be reachable in production. Known paths are confirmed only on a 200 with expected content markers, ranging from version disclosure to credential leaks.

**How it's exploited:** Exposed config (app/etc/local.xml, app/etc/env.php) hands an attacker the DB credentials and crypt key, enabling session forgery and store takeover. An open setup wizard or downloader lets an attacker install malicious extensions.

**Fix:** Block public access to setup, downloader, app/etc, and var/log, move the admin panel off the default URL, and rotate any exposed credentials or crypt key.`

	ModuleConfirmation = "Confirmed when probed Magento endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"magento", "php", "cms", "misconfiguration", "light"}
)
