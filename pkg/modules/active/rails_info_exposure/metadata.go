package rails_info_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-info-exposure"
	ModuleName  = "Rails Info Exposure"
	ModuleShort = "Detects exposed Rails development and debug endpoints in production"
)

var (
	ModuleDesc = `## Description
Probes for Rails development-oriented endpoints that are commonly left exposed in
production deployments. Checks for informational pages (/rails/info), mailer previews
(/rails/mailers), Action Mailbox conductor UI, and health endpoints that leak metadata.

## Notes
- Sends GET requests to known Rails development endpoints
- Fingerprints 404 responses to avoid false positives from custom error pages
- Checks for Rails-specific content markers in response bodies
- Reports exposed endpoints with appropriate severity levels

## References
- https://guides.rubyonrails.org/configuring.html
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when Rails development endpoints return 200 with framework-specific content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
