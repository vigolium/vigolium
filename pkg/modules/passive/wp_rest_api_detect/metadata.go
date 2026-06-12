package wp_rest_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-rest-api-detect"
	ModuleName  = "WordPress REST API Exposure"
	ModuleShort = "Detects exposed WordPress REST API namespaces and sensitive endpoints"
)

var (
	ModuleDesc = `**What it means:** The site exposes the WordPress REST API at /wp-json/, and this module passively observed its JSON responses disclosing information. The index lists every registered API namespace, including non-core plugin namespaces that widen the attack surface, and the wp/v2/users endpoint was seen returning account details (IDs, slugs, names) to an unauthenticated request, which is a privacy and brute-force exposure.

**How it's exploited:** An attacker maps the disclosed plugin namespaces to look up known vulnerabilities in those specific plugins and probe their endpoints, which often ship with weak or missing permission checks. Exposed user data from wp/v2/users yields valid login slugs (usernames) that fuel targeted password-guessing and phishing against accounts such as admin.

**Fix:** Restrict or authenticate the user-listing endpoint (for example via a security plugin or permission_callback) and remove or lock down unneeded plugin REST namespaces so they are not reachable unauthenticated.`

	ModuleConfirmation = "Confirmed when REST API responses contain namespace listings or user data accessible without authentication"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "api", "light"}
)
