package magento_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "magento-misconfig"
	ModuleName  = "Magento Misconfiguration"
	ModuleShort = "Detects exposed Magento setup wizard, downloader, version files, and admin panels"
)

var (
	ModuleDesc = `**What it means:** A Magento or Adobe Commerce store is exposing files or interfaces that should never be reachable in production. The module probes a set of known Magento 1.x and 2.x paths and confirms each one only when the response returns 200 with the expected content markers (validated against a per-host 404 fingerprint to cut false positives). The impact ranges from low-severity version disclosure to critical credential leaks depending on which path responds.

**How it's exploited:** Exposed config files (app/etc/local.xml, app/etc/env.php) hand an attacker the database credentials and the crypt key, which decrypts stored secrets and enables admin-cookie/session forgery and full store takeover. An open setup wizard or downloader (Magento Connect) lets an attacker reconfigure the store or install malicious extensions, and leaked logs, module lists, and version files map the exact build so attackers can target known Magento CVEs.

**Fix:** Block public access to setup, downloader, app/etc, and var/log paths, move the admin panel off the default URL, and rotate any credentials or crypt key that were exposed.`

	ModuleConfirmation = "Confirmed when probed Magento endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"magento", "php", "cms", "misconfiguration", "light"}
)
