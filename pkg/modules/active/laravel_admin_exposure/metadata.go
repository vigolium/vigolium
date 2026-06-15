package laravel_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-admin-exposure"
	ModuleName  = "Laravel Admin Exposure"
	ModuleShort = "Detects unauthenticated access to Laravel admin panels, API documentation, and GraphQL endpoints"
)

var (
	ModuleDesc = `**What it means:** A Laravel admin or developer surface is reachable without authentication: an admin panel (Nova, Filament, Backpack, Voyager, /admin), an OpenAPI/Swagger spec, a login page, or a GraphQL endpoint with introspection.

**How it's exploited:** An open admin panel lets an attacker reach management actions and data directly. An exposed OpenAPI spec or GraphQL introspection hands over every endpoint, parameter, and type, and a login page confirms which framework is installed for version-specific attacks.

**Fix:** Place admin panels, API documentation, and GraphQL introspection behind authentication or IP allowlists, or disable them in production.`

	ModuleConfirmation = "Heuristic: an endpoint returns 200 satisfying every framework/endpoint-specific marker group (an anchor token plus corroboration) that survives a reflected-path strip, is not a login wall, is not the same shell served at the base path, and is not reproduced by a nonexistent sibling path (catch-all). A bare generic token (login/email/admin/data) never confirms on its own. Reported Tentative; warrants manual confirmation."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"laravel", "php", "info-disclosure", "probe", "light"}
)
