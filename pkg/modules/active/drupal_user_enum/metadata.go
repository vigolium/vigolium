package drupal_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-user-enum"
	ModuleName  = "Drupal User Enumeration"
	ModuleShort = "Detects Drupal user enumeration via user profile paths and JSON:API"
)

var (
	ModuleDesc = `**What it means:** This Drupal site lets an unauthenticated visitor enumerate valid account usernames. The scanner confirmed leakage either through numeric profile paths (/user/1 through /user/5 redirecting to /users/<username> or rendering a Drupal profile page whose title shows the username) or through the JSON:API endpoint /jsonapi/user/user returning user objects to anonymous requests. Knowing real usernames is a security problem because it removes the guesswork from account-takeover attacks.

**How it's exploited:** An attacker harvests the confirmed usernames and feeds them into credential-stuffing, password-spraying, or targeted brute-force attacks against the login form, and uses leaked profile metadata for phishing or social engineering. The JSON:API listing can also expose additional account fields and the membership roster, widening the attack surface.

**Fix:** Restrict anonymous access to user profiles and the JSON:API user resource (require authentication or disable the JSON:API module if unused), and avoid exposing usernames in profile URLs and page titles.`

	ModuleConfirmation = "Confirmed when /user/N profile paths leak distinct usernames (via /users/<name> redirect or a Drupal-corroborated 200 profile title that differs from the unknown-user baseline) or JSON:API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "php", "info-disclosure", "probe", "moderate"}
)
