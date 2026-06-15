package wp_rest_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-rest-api-detect"
	ModuleName  = "WordPress REST API Exposure"
	ModuleShort = "Detects exposed WordPress REST API namespaces and sensitive endpoints"
)

var (
	ModuleDesc = `**What it means:** The site exposes the WordPress REST API at /wp-json/ with disclosing JSON responses. The index lists every registered namespace, including non-core plugin namespaces, and wp/v2/users returned account details (IDs, slugs, names) to an unauthenticated request - a privacy and brute-force exposure.

**How it's exploited:** An attacker maps the disclosed plugin namespaces to look up known vulnerabilities and probe endpoints with weak permission checks. Exposed wp/v2/users data yields valid usernames that fuel targeted password-guessing and phishing against accounts such as admin.

**Fix:** Restrict or authenticate the user-listing endpoint (via permission_callback) and lock down unneeded plugin REST namespaces.`

	ModuleConfirmation = "Confirmed when REST API responses contain namespace listings or user data accessible without authentication"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "api", "light"}
)
