package api_key_url_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-key-url-exposure"
	ModuleName  = "API Key in URL"
	ModuleShort = "Detects API keys that work when moved from headers to URL parameters"
)

var (
	ModuleDesc = `## Description
Detects API keys and authentication tokens that continue to work when moved from
HTTP headers to URL query parameters. API keys in URLs are logged in access logs,
browser history, referrer headers, and proxy logs, significantly increasing the
risk of credential exposure.

## Notes
- Tests once per unique host+path combination
- Checks common auth headers: Authorization, X-API-Key, X-Auth-Token, etc.
- Only tests the first matching auth header per request
- Reports when response with URL parameter matches original 2xx status

## References
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- https://cwe.mitre.org/data/definitions/598.html`

	ModuleConfirmation = "Confirmed when the server returns a successful response with the API key passed as a URL query parameter instead of in the authorization header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "api-security", "light"}
)
