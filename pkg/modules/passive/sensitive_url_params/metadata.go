package sensitive_url_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-sensitive-url-params"
	ModuleName  = "Sensitive URL Params"
	ModuleShort = "Detects sensitive data in URL query parameters"
)

var (
	ModuleDesc = `## Description
Passively detects sensitive information passed via URL query parameters, which may
be logged in server logs, browser history, and referrer headers.

## Notes
- Detects passwords, tokens, API keys, and credentials in URL parameters
- Pattern-based detection on both parameter names and values
- Sensitive data in URLs is logged and may leak via Referer headers

## References
- https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url
- https://cwe.mitre.org/data/definitions/598.html`

	ModuleConfirmation = "Indicated when URL query parameters contain names or values matching sensitive data patterns (password, token, key, secret)"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"info-disclosure", "light"}
)
