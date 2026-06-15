package rails_info_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-info-exposure"
	ModuleName  = "Rails Info Exposure"
	ModuleShort = "Detects exposed Rails development and debug endpoints in production"
)

var (
	ModuleDesc = `**What it means:** Ruby on Rails development and debug endpoints are reachable in production, exposing the Rails/Ruby version, environment config, the full route map, Action Mailer previews, or the Action Mailbox conductor UI - pages meant only for local development.

**How it's exploited:** An attacker browses /rails/info, /rails/info/routes, /rails/mailers, or /rails/conductor/action_mailbox/inbound_emails and reads the data. Version strings pin known CVEs, the route listing maps the attack surface including hidden admin and API endpoints, and mailer previews can reveal templates and embedded tokens.

**Fix:** Run the app in production mode, restrict or remove these endpoints, and block /rails/* at the proxy.`

	ModuleConfirmation = "Confirmed when Rails development endpoints return 200 with framework-specific content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
