package php_framework_debug

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-framework-debug"
	ModuleName  = "PHP Framework Debug Exposure"
	ModuleShort = "Detects exposed debug endpoints for Yii, CodeIgniter, CakePHP, and other PHP frameworks"
)

var (
	ModuleDesc = `**What it means:** A debug, profiler, or developer tool belonging to a PHP framework is reachable in production. The module probes known endpoints for Yii (debug module, Gii code generator), CodeIgniter (user guide, application logs), CakePHP DebugKit, Slim, FuelPHP, and Phalcon DevTools, confirming each with framework-specific content markers and a 404-baseline comparison so it only reports a page that genuinely exists. These tools leak request logs, SQL queries, stack traces, file paths, and application configuration that should never be public.

**How it's exploited:** An attacker browses the exposed panel to map internal routes, read database queries and config secrets, and harvest absolute server paths for use in further attacks. The most dangerous cases (Yii Gii, Phalcon DevTools) can generate or scaffold code and run database migrations, turning information disclosure into code execution or data tampering; the rest fingerprint the exact framework and version for targeting known CVEs.

**Fix:** Disable debug mode and remove or access-restrict all framework development tools and log directories in production deployments.`

	ModuleConfirmation = "Confirmed when probed framework debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
