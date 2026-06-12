package php_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-debug-exposure"
	ModuleName  = "PHP Debug Exposure"
	ModuleShort = "Detects exposed phpinfo pages, PHP-FPM status endpoints, and phpMyAdmin instances"
)

var (
	ModuleDesc = `**What it means:** A PHP debug or administration endpoint that should not be reachable from the public internet is exposed and returns its real content. This module confirms one of three classes: a phpinfo() page (at paths like /info.php, /test.php, /debug.php), a PHP-FPM status or ping endpoint, or a phpMyAdmin database management interface, each verified by matching expected content markers against a live 200 response and discarding custom 404 pages.

**How it's exploited:** A phpinfo() page leaks the exact PHP version, loaded extensions, file paths, and environment configuration, which an attacker uses to map the server and select version-specific exploits. PHP-FPM status pages disclose pool internals and in-flight request URIs and script paths, while an exposed phpMyAdmin reachable without controls can be brute-forced or abused to read and modify the database directly.

**Fix:** Remove these debug pages from production and restrict phpMyAdmin and PHP-FPM status endpoints to trusted networks behind authentication.`

	ModuleConfirmation = "Confirmed when probed PHP debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
