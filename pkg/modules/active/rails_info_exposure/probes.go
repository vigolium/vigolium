package rails_info_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	{
		path:    "/rails/info",
		name:    "Rails Info Page",
		markers: []string{"Rails version", "Ruby version", "Application root"},
		sev:     severity.High,
		desc:    "Rails info page is exposed, revealing framework version, Ruby version, and application root path",
	},
	{
		path:    "/rails/info/properties",
		name:    "Rails Info Properties",
		markers: []string{"Rails version", "Ruby version", "Rack version"},
		sev:     severity.High,
		desc:    "Rails info properties endpoint is exposed, disclosing detailed environment configuration",
	},
	{
		path:    "/rails/info/routes",
		name:    "Rails Info Routes",
		markers: []string{"URI Pattern", "Controller#Action"},
		sev:     severity.High,
		desc:    "Rails route listing is exposed, revealing all application routes and controller actions",
	},
	{
		path:    "/rails/mailers",
		name:    "Action Mailer Previews",
		markers: []string{"Action Mailer Previews", "Rails Mailers", "Mailer Previews"},
		sev:     severity.Medium,
		desc:    "Action Mailer preview pages are accessible, potentially exposing email templates and embedded tokens",
	},
	{
		path:    "/rails/conductor/action_mailbox/inbound_emails",
		name:    "Action Mailbox Conductor UI",
		markers: []string{"Action Mailbox", "Inbound Emails"},
		sev:     severity.Medium,
		desc:    "Action Mailbox conductor UI is accessible, exposing inbound email content and processing status",
	},
	{
		path:    "/up",
		name:    "Rails Health Check (/up)",
		markers: []string{},
		sev:     severity.Info,
		desc:    "Rails health check endpoint is accessible",
	},
}
