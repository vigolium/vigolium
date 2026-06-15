package symfony_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-misconfig"
	ModuleName  = "Symfony Misconfiguration"
	ModuleShort = "Detects exposed Symfony profiler, debug toolbar, dev front controller, and configuration leaks"
)

var (
	ModuleDesc = `**What it means:** A Symfony app exposes development resources that should never be reachable in production - the web profiler or debug toolbar, the app_dev.php front controller, log files, or framework/Doctrine config files served as readable content.

**How it's exploited:** An attacker browses the profiler for request data, routes, and settings. Config is highest impact: framework.yaml can reveal the secret key and doctrine.yaml can disclose database credentials.

**Fix:** Disable the profiler, debug toolbar, and dev front controller in production, set the environment to prod with debug off, and never serve config or log files from the web root.`

	ModuleConfirmation = "Confirmed when probed Symfony endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"symfony", "php", "misconfiguration", "info-disclosure", "light"}
)
