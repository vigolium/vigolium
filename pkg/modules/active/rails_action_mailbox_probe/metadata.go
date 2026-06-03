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
- The conductor UI is confirmed by GETting the page and matching the actual
  rendered Action Mailbox conductor content — never on status or headers alone
- POST-only ingress routes (relay, SendGrid, Mailgun, Mandrill, Postmark) have
  no rendered body; they are confirmed via a genuine Rails Allow: POST on OPTIONS
- Rejects generic CORS preflights (Access-Control-Allow-* with no Allow header),
  the API-gateway/proxy reply to OPTIONS on every path
- Fingerprints 404 responses and strips reflected request paths to avoid false positives

## References
- https://guides.rubyonrails.org/action_mailbox_basics.html
- https://api.rubyonrails.org/classes/ActionMailbox.html`

	ModuleConfirmation = "Confirmed when Action Mailbox ingress endpoints respond to requests without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "light"}
)
