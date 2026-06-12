package wp_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-user-enum"
	ModuleName  = "WordPress User Enumeration"
	ModuleShort = "Detects WordPress user enumeration via author archives and REST API"
)

var (
	ModuleDesc = `**What it means:** This WordPress site leaks valid account usernames to unauthenticated visitors. The scanner confirmed enumeration through author archives (requesting /?author=N for IDs 1 through 5 returns a 301/302 redirect to /author/<username>/, exposing the login slug) and/or the public REST API (/wp-json/wp/v2/users returns JSON user objects whose slug fields are the usernames). Usernames are meant to be private; disclosing them removes a meaningful layer of secrecy from the login.

**How it's exploited:** An attacker harvests the real usernames (including the administrator) and uses them as the known half of a credential pair for password brute-force, password-spraying, or credential-stuffing attacks against /wp-login.php or XML-RPC, dramatically improving their odds of account takeover. The list also aids targeted phishing of named site operators.

**Fix:** Block author-scan redirects and restrict the REST users endpoint to authenticated requests (for example via a security plugin or web-server rules), and enforce strong passwords plus login rate-limiting or 2FA.`

	ModuleConfirmation = "Confirmed when author archive redirects expose usernames or REST API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"wordpress", "cms", "php", "authentication", "light"}
)
