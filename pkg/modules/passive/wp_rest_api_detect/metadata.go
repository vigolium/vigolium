package wp_rest_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-rest-api-detect"
	ModuleName  = "WordPress REST API Exposure"
	ModuleShort = "Detects exposed WordPress REST API namespaces and sensitive endpoints"
)

var (
	ModuleDesc = `## Description
Passively detects WordPress REST API exposure by analyzing responses from
/wp-json/ endpoints. Identifies non-core plugin namespaces that may have
weak or missing permission_callback, and flags unauthenticated access to
sensitive built-in endpoints like wp/v2/users and wp/v2/settings.

## Notes
- Passive only: does not send any HTTP requests
- Analyzes JSON responses from wp-json endpoints
- Flags custom plugin namespaces (non-core) as potential attack surface
- Detects user data exposure in wp/v2/users responses
- Deduplicates by host

## References
- https://developer.wordpress.org/rest-api/
- https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/`

	ModuleConfirmation = "Confirmed when REST API responses contain namespace listings or user data accessible without authentication"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"wordpress", "cms", "php", "api", "light"}
)
