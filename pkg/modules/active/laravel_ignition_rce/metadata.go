package laravel_ignition_rce

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-ignition-rce"
	ModuleName  = "Laravel Ignition RCE"
	ModuleShort = "Detects exposed Ignition endpoints and flags CVE-2021-3129 RCE candidates"
)

var (
	ModuleDesc = `**What it means:** The application exposes Laravel's Ignition debug error-page tooling (endpoints under /_ignition/, such as health-check, execute-solution, and script/style assets) to unauthenticated visitors. Ignition is a development-only debugger that must never be reachable in production; its presence indicates debug mode is left enabled.
**How it's exploited:** An attacker reaching the execute-solution endpoint on a vulnerable Ignition (facade/ignition before 2.5.2, Laravel before 8.4.2) can chain CVE-2021-3129 to gain remote code execution on the server by writing and corrupting a log file into a malicious phar/PHP payload. Even where the version is patched, exposed Ignition assets and health-check confirm debug tooling is live, leaking framework internals and stack traces that aid further attacks.
**Fix:** Set APP_DEBUG=false (production environment) so Ignition is disabled, and upgrade facade/ignition to 2.5.2 or later.`

	ModuleConfirmation = "Confirmed when Ignition endpoints are reachable and return expected framework-specific markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "rce", "light"}
)
