package php_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-debug-exposure"
	ModuleName  = "PHP Debug Exposure"
	ModuleShort = "Detects exposed phpinfo pages, PHP-FPM status endpoints, and phpMyAdmin instances"
)

var (
	ModuleDesc = `**What it means:** A PHP debug or admin endpoint that should not be public is exposed and returns real content. The check confirms one of three classes: a phpinfo() page (/info.php, /test.php), a PHP-FPM status or ping endpoint, or a phpMyAdmin interface.

**How it's exploited:** A phpinfo() page leaks the PHP version, extensions, file paths, and environment, helping an attacker select version-specific exploits. PHP-FPM status discloses in-flight request URIs and script paths, and an open phpMyAdmin can be brute-forced.

**Fix:** Remove debug pages from production and restrict phpMyAdmin and PHP-FPM status to trusted networks behind authentication.`

	ModuleConfirmation = "Confirmed when probed PHP debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
