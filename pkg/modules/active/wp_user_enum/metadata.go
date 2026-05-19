package wp_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-user-enum"
	ModuleName  = "WordPress User Enumeration"
	ModuleShort = "Detects WordPress user enumeration via author archives and REST API"
)

var (
	ModuleDesc = `## Description
Tests for WordPress user enumeration through two vectors:
1. Author archive redirects: /?author=N redirects to /author/<username>/
2. REST API user listing: /wp-json/wp/v2/users returns user objects with slugs

Enumerated usernames can be used for password brute-force attacks.

## Notes
- Runs once per host
- Tests author IDs 1 through 5
- Checks REST API with and without per_page parameter
- Non-destructive: only performs GET requests

## References
- https://www.wpbeginner.com/plugins/how-to-discourage-brute-force-by-blocking-author-scans-in-wordpress/
- https://developer.wordpress.org/rest-api/reference/users/`

	ModuleConfirmation = "Confirmed when author archive redirects expose usernames or REST API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "authentication", "light"}
)
