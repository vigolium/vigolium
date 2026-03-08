package rails_active_storage_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	method      string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	{
		path:    "/rails/active_storage/direct_uploads",
		method:  "OPTIONS",
		name:    "Active Storage Direct Upload",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Active Storage direct upload endpoint is accessible. If unauthenticated, attackers may upload arbitrary files",
	},
	{
		path:    "/rails/active_storage/blobs/redirect",
		method:  "GET",
		name:    "Active Storage Blob Route",
		markers: []string{},
		sev:     severity.Low,
		desc:    "Active Storage blob routes are enabled, indicating Active Storage is in use and may serve files publicly",
	},
	{
		path:    "/rails/action_mailbox/relay/inbound_emails",
		method:  "OPTIONS",
		name:    "Action Mailbox Relay Ingress",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Action Mailbox relay ingress endpoint is accessible",
	},
	{
		path:    "/rails/action_mailbox/sendgrid/inbound_emails",
		method:  "OPTIONS",
		name:    "Action Mailbox SendGrid Ingress",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Action Mailbox SendGrid ingress endpoint is accessible and may accept unauthorized submissions",
	},
	{
		path:    "/rails/action_mailbox/mailgun/inbound_emails/mime",
		method:  "OPTIONS",
		name:    "Action Mailbox Mailgun Ingress",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Action Mailbox Mailgun ingress endpoint is accessible",
	},
	{
		path:    "/rails/action_mailbox/mandrill/inbound_emails",
		method:  "OPTIONS",
		name:    "Action Mailbox Mandrill Ingress",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Action Mailbox Mandrill ingress endpoint is accessible",
	},
	{
		path:    "/rails/action_mailbox/postmark/inbound_emails",
		method:  "OPTIONS",
		name:    "Action Mailbox Postmark Ingress",
		markers: []string{"POST", "Allow"},
		sev:     severity.Medium,
		desc:    "Action Mailbox Postmark ingress endpoint is accessible",
	},
}
