package rails_action_mailbox_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-action-mailbox-probe"
	ModuleName  = "Rails Action Mailbox Probe"
	ModuleShort = "Detects exposed Rails Action Mailbox ingress endpoints that may accept unauthorized submissions"
)

var (
	ModuleDesc = `## Description
Probes for Rails Action Mailbox ingress endpoints for multiple email service providers.
These endpoints receive inbound emails via HTTP and may be accessible without proper
authentication or provider signature validation.

## Notes
- Uses OPTIONS and POST requests to check for accessible ingress endpoints
- Tests relay, SendGrid, Mailgun, Mandrill, and Postmark ingress paths
- Checks for WWW-Authenticate headers indicating basic auth protection
- Fingerprints 404 responses to avoid false positives

## References
- https://guides.rubyonrails.org/action_mailbox_basics.html
- https://api.rubyonrails.org/classes/ActionMailbox.html`

	ModuleConfirmation = "Confirmed when Action Mailbox ingress endpoints respond to requests without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"rails", "ruby", "misconfiguration", "light"}
)
