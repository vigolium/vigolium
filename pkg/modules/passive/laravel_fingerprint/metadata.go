package laravel_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-fingerprint"
	ModuleName  = "Laravel Fingerprint"
	ModuleShort = "Identifies Laravel installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The app is built on the Laravel PHP framework, identified from at least two signals such as laravel_session or XSRF-TOKEN cookies, a csrf-token meta tag, Illuminate error strings, an Ignition or Whoops debug handler, or Sanctum/Passport. Informational recon, not a vulnerability.

**How it's exploited:** An attacker targets Laravel-specific weaknesses - known CVEs in Laravel, Ignition (CVE-2021-3129 RCE), or Passport. An exposed Ignition or Whoops handler signals debug mode that can leak source, config, and environment details.

**Fix:** Remove the X-Powered-By header and verbose error pages, and disable debug mode (APP_DEBUG) in production.`

	ModuleConfirmation = "Confirmed when 2+ independent Laravel-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"laravel", "php", "fingerprint", "light"}
)
