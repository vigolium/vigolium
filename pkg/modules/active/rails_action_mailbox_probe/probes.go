package rails_action_mailbox_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path string
	name string
	sev  severity.Severity
	desc string
}

var probes = []probe{
	{
		path: "/rails/action_mailbox/relay/inbound_emails",
		name: "Action Mailbox Relay Ingress",
		sev:  severity.Medium,
		desc: "Action Mailbox relay ingress endpoint is accessible and may accept unauthorized email submissions",
	},
	{
		path: "/rails/action_mailbox/sendgrid/inbound_emails",
		name: "Action Mailbox SendGrid Ingress",
		sev:  severity.Medium,
		desc: "Action Mailbox SendGrid ingress endpoint is accessible without provider signature validation",
	},
	{
		path: "/rails/action_mailbox/mailgun/inbound_emails/mime",
		name: "Action Mailbox Mailgun Ingress",
		sev:  severity.Medium,
		desc: "Action Mailbox Mailgun ingress endpoint is accessible without provider signature validation",
	},
	{
		path: "/rails/action_mailbox/mandrill/inbound_emails",
		name: "Action Mailbox Mandrill Ingress",
		sev:  severity.Medium,
		desc: "Action Mailbox Mandrill ingress endpoint is accessible without provider signature validation",
	},
	{
		path: "/rails/action_mailbox/postmark/inbound_emails",
		name: "Action Mailbox Postmark Ingress",
		sev:  severity.Medium,
		desc: "Action Mailbox Postmark ingress endpoint is accessible without provider signature validation",
	},
	{
		path: "/rails/conductor/action_mailbox/inbound_emails",
		name: "Action Mailbox Conductor UI",
		sev:  severity.High,
		desc: "Action Mailbox conductor development UI is accessible in production, exposing inbound email content and processing status",
	},
}
