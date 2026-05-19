package laravel_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-admin-exposure"
	ModuleName  = "Laravel Admin Exposure"
	ModuleShort = "Detects unauthenticated access to Laravel admin panels, API documentation, and GraphQL endpoints"
)

var (
	ModuleDesc = `## Description
Probes for unauthenticated access to Laravel admin panels (Nova, Filament,
Backpack, Voyager), API documentation endpoints (Swagger UI, L5-Swagger,
Scramble, OpenAPI specs), and GraphQL endpoints with introspection enabled.
These surfaces increase attack surface and may expose sensitive data or
admin functionality.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Admin panels reported as high severity; API docs as informational/low

## References
- https://nova.laravel.com/docs
- https://filamentphp.com/docs
- https://lighthouse-php.com/master/security/authentication.html`

	ModuleConfirmation = "Confirmed when admin or documentation endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "info-disclosure", "probe", "light"}
)
