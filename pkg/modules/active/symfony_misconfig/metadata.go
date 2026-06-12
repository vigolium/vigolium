package symfony_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-misconfig"
	ModuleName  = "Symfony Misconfiguration"
	ModuleShort = "Detects exposed Symfony profiler, debug toolbar, dev front controller, and configuration leaks"
)

var (
	ModuleDesc = `**What it means:** A Symfony application is exposing development and debug resources that should never be reachable in production. The scanner found at least one of: the web profiler or debug toolbar, the app_dev.php dev front controller, dev/prod log files, or framework, Doctrine, security, and bundle configuration files served as readable content. These leak internal application details and, in the worst cases, secrets.

**How it's exploited:** An attacker browses the profiler to read full request/response data, routes, and environment settings, enumerates debug tokens, and reads exposed log files for errors and security events. Exposed configuration is the highest impact: framework.yaml can reveal the application secret key, and doctrine.yaml can disclose database connection strings and credentials, giving a direct path to deeper compromise.

**Fix:** Disable the profiler, debug toolbar, and the dev front controller in production, set the environment to prod with debug off, and ensure config and log files are never served by the web root.`

	ModuleConfirmation = "Confirmed when probed Symfony endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"symfony", "php", "misconfiguration", "info-disclosure", "light"}
)
