package laravel_ignition_rce

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-ignition-rce"
	ModuleName  = "Laravel Ignition RCE"
	ModuleShort = "Detects exposed Ignition endpoints and flags CVE-2021-3129 RCE candidates"
)

var (
	ModuleDesc = `**What it means:** The app exposes Laravel's Ignition debug error-page tooling (endpoints under /_ignition/ such as health-check and execute-solution) to unauthenticated visitors. This development-only debugger must never run in production; its presence indicates debug mode is enabled.

**How it's exploited:** On a vulnerable Ignition (facade/ignition before 2.5.2, Laravel before 8.4.2), reaching execute-solution chains CVE-2021-3129 to gain remote code execution by corrupting a log file into a malicious phar payload. Even when patched, exposed Ignition assets leak framework internals and stack traces.

**Fix:** Set APP_DEBUG=false in production so Ignition is disabled, and upgrade facade/ignition to 2.5.2 or later.`

	ModuleConfirmation = "Confirmed when Ignition endpoints are reachable and return expected framework-specific markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "rce", "light"}
)
