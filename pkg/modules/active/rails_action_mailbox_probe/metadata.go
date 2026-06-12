package rails_action_mailbox_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-action-mailbox-probe"
	ModuleName  = "Rails Action Mailbox Probe"
	ModuleShort = "Detects exposed Rails Action Mailbox ingress endpoints that may accept unauthorized submissions"
)

var (
	ModuleDesc = `**What it means:** A Ruby on Rails application is exposing Action Mailbox ingress endpoints, which receive inbound emails over HTTP from providers such as SendGrid, Mailgun, Mandrill, Postmark, or the generic relay. The module confirms the POST-only ingress routes via a genuine Rails Allow: POST response to OPTIONS, and confirms the conductor development UI by matching its rendered HTML content. When these routes are reachable without authentication or provider signature validation, untrusted parties can interact with the application's email-processing pipeline, and an exposed conductor UI leaks inbound email contents and processing state.

**How it's exploited:** An attacker submits forged inbound-email payloads directly to the ingress endpoint, bypassing the email provider, to inject spoofed messages into application workflows (account flows, ticketing, parsing logic) or trigger downstream abuse. An exposed conductor UI lets an attacker browse received emails and craft test deliveries.

**Fix:** Require provider signature/credential validation on Action Mailbox ingress routes and ensure the conductor UI is disabled or access-restricted in production.`

	ModuleConfirmation = "Confirmed when Action Mailbox ingress endpoints respond to requests without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "light"}
)
