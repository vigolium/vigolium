package laravel_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-fingerprint"
	ModuleName  = "Laravel Fingerprint"
	ModuleShort = "Identifies Laravel installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Laravel installations by analyzing HTTP response headers,
cookies (laravel_session, XSRF-TOKEN), body patterns (csrf-token meta tag,
Illuminate error strings), and Sanctum/Passport indicators. Requires 2+
independent signals to avoid false positives.

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host to avoid redundant processing
- Extracts version hints from error pages and headers when available
- Reports as informational severity

## References
- https://laravel.com/docs/csrf
- https://laravel.com/docs/session
- https://laravel.com/docs/sanctum`

	ModuleConfirmation = "Confirmed when 2+ independent Laravel-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"laravel", "php", "fingerprint", "light"}
)
