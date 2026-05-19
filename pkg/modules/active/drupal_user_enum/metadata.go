package drupal_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-user-enum"
	ModuleName  = "Drupal User Enumeration"
	ModuleShort = "Detects Drupal user enumeration via user profile paths and JSON:API"
)

var (
	ModuleDesc = `## Description
Tests for Drupal user enumeration through two vectors:
1. User profile paths: /user/1 through /user/5, checking for redirects to /users/<username>
2. JSON:API user listing: /jsonapi/user/user returns user objects anonymously

Enumerated usernames can be used for password brute-force attacks.

## Notes
- Runs once per host
- Tests user IDs 1 through 5
- Checks JSON:API endpoint for anonymous user data access
- Non-destructive: only performs GET requests

## References
- https://www.drupal.org/docs/security-in-drupal
- https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module`

	ModuleConfirmation = "Confirmed when user profile paths expose usernames or JSON:API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "php", "info-disclosure", "probe", "moderate"}
)
