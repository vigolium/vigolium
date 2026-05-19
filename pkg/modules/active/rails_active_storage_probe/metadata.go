package rails_active_storage_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-probe"
	ModuleName  = "Rails Active Storage Probe"
	ModuleShort = "Detects exposed Rails Active Storage direct upload and Action Mailbox ingress endpoints"
)

var (
	ModuleDesc = `## Description
Probes for Rails Active Storage direct upload endpoints that may accept unauthenticated
uploads, and Action Mailbox ingress endpoints that may accept unauthorized email submissions.
Also checks for publicly accessible Active Storage blob routes.

## Notes
- Uses OPTIONS requests for direct upload endpoint to check allowed methods
- Probes Action Mailbox ingress paths for multiple email providers
- Fingerprints 404 responses to avoid false positives

## References
- https://guides.rubyonrails.org/active_storage_overview.html
- https://guides.rubyonrails.org/action_mailbox_basics.html`

	ModuleConfirmation = "Confirmed when Active Storage or Action Mailbox endpoints respond with expected behavior"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "file-exposure", "light"}
)
