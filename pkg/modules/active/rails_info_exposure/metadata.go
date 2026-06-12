package rails_info_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-info-exposure"
	ModuleName  = "Rails Info Exposure"
	ModuleShort = "Detects exposed Rails development and debug endpoints in production"
)

var (
	ModuleDesc = `**What it means:** Ruby on Rails development and debug endpoints are reachable on this deployment. Depending on the endpoint hit, this exposes the Rails and Ruby version, environment configuration, the full application route map, Action Mailer preview templates, the Action Mailbox conductor UI, or a health-check page. These pages are meant for local development and should not be served in production, where they leak internal application detail.

**How it's exploited:** An attacker browses to paths such as /rails/info, /rails/info/routes, /rails/mailers, or /rails/conductor/action_mailbox/inbound_emails and reads the disclosed data directly. Exposed version strings let them pin known Rails/Ruby CVEs to this target; the route listing maps the entire attack surface (including hidden admin and API endpoints); mailer previews and the mailbox conductor can reveal email templates, embedded tokens, and inbound message content.

**Fix:** Ensure the app runs in the production environment and restrict or remove these development endpoints (config.consider_all_requests_local off, route mailer/conductor mounts behind authentication or only in development), and block /rails/* paths at the proxy in production.`

	ModuleConfirmation = "Confirmed when Rails development endpoints return 200 with framework-specific content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
