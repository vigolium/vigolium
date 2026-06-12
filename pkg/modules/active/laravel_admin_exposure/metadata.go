package laravel_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-admin-exposure"
	ModuleName  = "Laravel Admin Exposure"
	ModuleShort = "Detects unauthenticated access to Laravel admin panels, API documentation, and GraphQL endpoints"
)

var (
	ModuleDesc = `**What it means:** A Laravel-related administrative or developer surface was reachable without authentication. Depending on the probe, this is an exposed admin panel (Nova, Filament, Backpack, Voyager, or a generic /admin or /backoffice), a published API documentation or OpenAPI spec endpoint (L5-Swagger, Scramble, openapi.json/yaml), an exposed framework login page, or a GraphQL endpoint with schema introspection enabled. These expose privileged functionality or map out the application's internal attack surface.

**How it's exploited:** An open admin panel lets an attacker reach management actions and data directly, severity depending on whether further auth gates exist. An exposed OpenAPI spec or GraphQL introspection result hands the attacker the full list of endpoints, parameters, and data types to target, and a visible login page confirms which admin framework is installed for version-specific follow-up attacks.

**Fix:** Place admin panels, API documentation, and GraphQL introspection behind authentication, IP allowlists, or disable them in production.`

	ModuleConfirmation = "Confirmed when admin or documentation endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "info-disclosure", "probe", "light"}
)
