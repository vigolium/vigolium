package wp_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-user-enum"
	ModuleName  = "WordPress User Enumeration"
	ModuleShort = "Detects WordPress user enumeration via author archives and REST API"
)

var (
	ModuleDesc = `**What it means:** This WordPress site leaks valid usernames to unauthenticated visitors via author archives (/?author=N redirects to /author/<username>/) and/or the public REST API (/wp-json/wp/v2/users returns JSON objects whose slug fields are usernames). Usernames are meant to be private.

**How it's exploited:** An attacker harvests the real usernames (including the administrator) as the known half for password brute-force, spraying, or credential-stuffing against /wp-login.php or XML-RPC, improving their odds of takeover. The list also aids targeted phishing.

**Fix:** Block author-scan redirects, restrict the REST users endpoint to authenticated requests, and enforce strong passwords plus login rate-limiting or 2FA.`

	ModuleConfirmation = "Confirmed when author archive redirects expose usernames or REST API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "authentication", "light"}
)
