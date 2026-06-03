package rails_action_mailbox_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path   string
	method string
	name   string
	sev    severity.Severity
	desc   string
	// bodyMarkers are genuine rendered-content strings that must appear in the
	// response body to confirm the finding. Used for GET probes against pages
	// that actually render HTML (the conductor UI). Empty for OPTIONS probes of
	// POST-only ingress routes, which have no inspectable body.
	bodyMarkers []string
}

var probes = []probe{
	// Ingress endpoints are POST-only API routes with no rendered body. A
	// genuine Rails route advertises POST via the standard Allow header on
	// OPTIONS; a generic CORS preflight (Access-Control-Allow-* only) is
	// rejected, so these are confirmed by a real route signal, not bare status.
	{
		path:   "/rails/action_mailbox/relay/inbound_emails",
		method: "OPTIONS",
		name:   "Action Mailbox Relay Ingress",
		sev:    severity.Medium,
		desc:   "Action Mailbox relay ingress endpoint is accessible and may accept unauthorized email submissions",
	},
	{
		path:   "/rails/action_mailbox/sendgrid/inbound_emails",
		method: "OPTIONS",
		name:   "Action Mailbox SendGrid Ingress",
		sev:    severity.Medium,
		desc:   "Action Mailbox SendGrid ingress endpoint is accessible without provider signature validation",
	},
	{
		path:   "/rails/action_mailbox/mailgun/inbound_emails/mime",
		method: "OPTIONS",
		name:   "Action Mailbox Mailgun Ingress",
		sev:    severity.Medium,
		desc:   "Action Mailbox Mailgun ingress endpoint is accessible without provider signature validation",
	},
	{
		path:   "/rails/action_mailbox/mandrill/inbound_emails",
		method: "OPTIONS",
		name:   "Action Mailbox Mandrill Ingress",
		sev:    severity.Medium,
		desc:   "Action Mailbox Mandrill ingress endpoint is accessible without provider signature validation",
	},
	{
		path:   "/rails/action_mailbox/postmark/inbound_emails",
		method: "OPTIONS",
		name:   "Action Mailbox Postmark Ingress",
		sev:    severity.Medium,
		desc:   "Action Mailbox Postmark ingress endpoint is accessible without provider signature validation",
	},
	// Conductor UI is a Rails-rendered HTML page. Confirm it by fetching the
	// page (GET) and matching the actual rendered content — never on the
	// response status or headers alone. These phrases are emitted by the Rails
	// Action Mailbox conductor index view and do not appear in the request path,
	// so a reflected path or empty 2xx cannot forge the match.
	{
		path:   "/rails/conductor/action_mailbox/inbound_emails",
		method: "GET",
		name:   "Action Mailbox Conductor UI",
		sev:    severity.High,
		desc:   "Action Mailbox conductor development UI is accessible in production, exposing inbound email content and processing status",
		bodyMarkers: []string{
			"Deliver new inbound email",
			"Inbound Emails",
			"ActionMailbox",
		},
	},
}
