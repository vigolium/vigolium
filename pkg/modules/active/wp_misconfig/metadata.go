package wp_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-wp-misconfig"
	ModuleName  = "WordPress Misconfiguration"
	ModuleShort = "Detects exposed WordPress configuration files, debug logs, and dangerous endpoints"
)

var (
	ModuleDesc = `## Description
Probes for WordPress-specific files and endpoints that should not be publicly
accessible: configuration backups, debug logs, installer/repair endpoints,
informational files, directory listings, and the externally triggerable cron.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to avoid false positives from WAF block pages
- Checks backup variants of wp-config.php (~, .old, .save, .swp, .txt)
- Detects exposed debug.log with PHP error/warning markers
- Checks directory listing on /wp-content/uploads/ and /wp-content/plugins/

## References
- https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/`

	ModuleConfirmation = "Confirmed when probed WordPress files return 200 with expected content markers (PHP constants, log entries, directory index HTML)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
