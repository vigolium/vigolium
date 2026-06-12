package rails_admin_dashboard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-admin-dashboard"
	ModuleName  = "Rails Admin Dashboard"
	ModuleShort = "Detects exposed Rails ecosystem admin panels and dashboard UIs"
)

var (
	ModuleDesc = `**What it means:** A Rails ecosystem admin panel or background-job dashboard is reachable at a predictable path and returned a working page (HTTP 200 with framework-specific UI markers), not a login screen or error. The module probes Sidekiq, GoodJob, Resque, Delayed Job, rack-mini-profiler, ActiveAdmin, and RailsAdmin, and uses a random-path 404 fingerprint plus anti-markers to avoid false positives. These interfaces are meant for internal operators and often ship without authentication.

**How it's exploited:** An attacker browses directly to the exposed dashboard and reads or manipulates whatever it surfaces: job queues, retry data, and sensitive job arguments (Sidekiq/GoodJob/Resque/Delayed Job), SQL queries and timing traces (rack-mini-profiler), or full administrative CRUD over application records (ActiveAdmin/RailsAdmin). This can leak internal data and, for the admin panels, allow privileged changes to application state.

**Fix:** Require authentication and authorization on every dashboard/admin mount, or disable the interface in production.`

	ModuleConfirmation = "Confirmed when Rails dashboard endpoints return responses containing framework-specific UI markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "info-disclosure", "light"}
)
