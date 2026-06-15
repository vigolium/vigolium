package rails_action_mailbox_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-action-mailbox-probe"
	ModuleName  = "Rails Action Mailbox Probe"
	ModuleShort = "Detects exposed Rails Action Mailbox ingress endpoints that may accept unauthorized submissions"
)

var (
	ModuleDesc = `**What it means:** A Ruby on Rails application exposes Action Mailbox ingress endpoints, which receive inbound emails over HTTP from providers such as SendGrid, Mailgun, and Postmark. The module confirms POST-only routes via a Rails Allow: POST response and the conductor UI by its HTML, reachable without authentication.

**How it's exploited:** An attacker submits forged inbound-email payloads to the ingress endpoint, bypassing the provider, to inject spoofed messages into application workflows. The conductor UI leaks received emails.

**Fix:** Require provider signature validation on ingress routes and disable the conductor UI in production.`

	ModuleConfirmation = "Confirmed when Action Mailbox ingress endpoints respond to requests without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "light"}
)
