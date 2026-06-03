package oauth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-misconfiguration"
	ModuleName  = "OAuth/OIDC Misconfiguration"
	ModuleShort = "Detects common OAuth/OIDC misconfigurations including open redirect and missing state"
)

var (
	ModuleDesc = `## Description
Detects common OAuth and OpenID Connect misconfigurations that can lead to account
takeover or authorization bypass. Tests for redirect_uri manipulation, missing CSRF
state parameter, and response_type downgrade to implicit flow.

## Notes
- Runs once per unique host+path combination via DiskSet dedup
- Only activates on detected OAuth/OIDC endpoints (path and parameter heuristics)
- Tests redirect_uri with multiple bypass techniques (direct replacement, subdomain confusion, path traversal)
- Checks for missing state parameter (CSRF protection)
- Tests response_type downgrade from code to token (implicit flow)

## References
- https://portswigger.net/web-security/oauth
- https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses`

	ModuleConfirmation = "Confirmed when an OAuth endpoint accepts a manipulated redirect_uri, is missing CSRF state protection, or accepts implicit flow downgrade"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "moderate"}
)
