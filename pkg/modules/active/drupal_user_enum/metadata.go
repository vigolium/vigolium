package drupal_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-user-enum"
	ModuleName  = "Drupal User Enumeration"
	ModuleShort = "Detects Drupal user enumeration via user profile paths and JSON:API"
)

var (
	ModuleDesc = `**What it means:** This Drupal site lets an unauthenticated visitor enumerate valid usernames, via numeric profile paths (/user/1 redirecting to /users/<username>) or the /jsonapi/user/user endpoint returning user objects to anonymous requests.

**How it's exploited:** An attacker harvests the usernames for credential-stuffing, password-spraying, and targeted brute-force against the login form, and uses leaked profile metadata for phishing.

**Fix:** Restrict anonymous access to user profiles and the JSON:API user resource (require auth or disable the module if unused), and avoid exposing usernames in profile URLs and titles.`

	ModuleConfirmation = "Confirmed when /user/N profile paths leak distinct usernames (via /users/<name> redirect or a Drupal-corroborated 200 profile title that differs from the unknown-user baseline) or JSON:API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "php", "info-disclosure", "probe", "moderate"}
)
