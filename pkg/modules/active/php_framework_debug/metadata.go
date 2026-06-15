package php_framework_debug

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-framework-debug"
	ModuleName  = "PHP Framework Debug Exposure"
	ModuleShort = "Detects exposed debug endpoints for Yii, CodeIgniter, CakePHP, and other PHP frameworks"
)

var (
	ModuleDesc = `**What it means:** A PHP framework debug or developer tool is reachable in production. The module probes endpoints for Yii (debug, Gii), CodeIgniter, CakePHP DebugKit, Slim, FuelPHP, and Phalcon DevTools, confirmed by framework-specific markers. These leak logs, SQL queries, stack traces, and configuration.

**How it's exploited:** An attacker maps routes, reads config secrets, and harvests server paths. Yii Gii and Phalcon DevTools scaffold code and run migrations, escalating to code execution; others fingerprint the version for known CVEs.

**Fix:** Disable debug mode and access-restrict framework dev tools and log directories in production.`

	ModuleConfirmation = "Confirmed when probed framework debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
