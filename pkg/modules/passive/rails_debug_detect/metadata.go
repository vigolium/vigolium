package rails_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-debug-detect"
	ModuleName  = "Rails Debug Detect"
	ModuleShort = "Detects Rails debug exception pages, Better Errors, Web Console, and ActiveRecord errors in responses"
)

var (
	ModuleDesc = `## Description
Passively detects Rails development/debug tooling exposed in production responses.
Identifies Rails exception pages with stack traces, Better Errors pages, Web Console
presence, ActiveRecord database errors, and absolute filesystem path disclosure.

## Notes
- Passive only: does not send any HTTP requests
- Checks for Rails-specific exception class names and debug section markers
- Detects Better Errors and Web Console development gems
- Identifies ActiveRecord/database error leakage
- Flags absolute filesystem path disclosure in responses

## References
- https://guides.rubyonrails.org/debugging_rails_applications.html
- https://owasp.org/www-community/Improper_Error_Handling`

	ModuleConfirmation = "Confirmed when Rails-specific debug patterns or exception details are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
