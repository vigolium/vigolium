package rails_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-rails-fingerprint"
	ModuleName  = "Rails Fingerprint"
	ModuleShort = "Identifies Ruby on Rails installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Ruby on Rails installations by analyzing HTTP response headers
(X-Request-Id, X-Runtime, Server), cookies (_session suffix), default error page
patterns, and body content markers (__VIEWSTATE absence with Rails patterns).

## Notes
- Passive only: does not send any HTTP requests
- Detects Rails via X-Request-Id + X-Runtime header combination
- Identifies Puma/Unicorn/Passenger server headers
- Recognizes default Rails 404/500 error page text
- Detects Rails session cookies by naming convention
- Deduplicates by host to avoid redundant processing

## References
- https://guides.rubyonrails.org/configuring.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server`

	ModuleConfirmation = "Confirmed when Rails-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"rails", "ruby", "fingerprint", "light"}
)
