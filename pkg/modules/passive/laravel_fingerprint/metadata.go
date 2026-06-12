package laravel_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-fingerprint"
	ModuleName  = "Laravel Fingerprint"
	ModuleShort = "Identifies Laravel installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The target application is built on the Laravel PHP framework, identified passively from at least two independent signals such as the laravel_session or XSRF-TOKEN cookies, a csrf-token meta tag, Illuminate error strings, an Ignition or Whoops debug error handler, or Sanctum and Passport indicators. This is an informational fingerprint, not a vulnerability, but it discloses the technology stack and sometimes the error-handling configuration to anyone inspecting responses.

**How it's exploited:** Knowing the app runs Laravel lets an attacker narrow their attack surface and target framework-specific weaknesses, for example known CVEs in Laravel, Ignition (CVE-2021-3129 RCE), or Passport, default routes like /sanctum/csrf-cookie, and predictable session or CSRF handling. An exposed Ignition or Whoops debug handler is an especially strong lead, since it usually signals a non-production debug mode that can leak source, config, and environment details.

**Fix:** Suppress framework fingerprints where practical by removing the X-Powered-By header and verbose error pages, and ensure debug mode (APP_DEBUG) is disabled in production so debug handlers never reach clients.`

	ModuleConfirmation = "Confirmed when 2+ independent Laravel-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"laravel", "php", "fingerprint", "light"}
)
