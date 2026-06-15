package rails_admin_dashboard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-admin-dashboard"
	ModuleName  = "Rails Admin Dashboard"
	ModuleShort = "Detects exposed Rails ecosystem admin panels and dashboard UIs"
)

var (
	ModuleDesc = `**What it means:** A Rails admin panel or background-job dashboard (Sidekiq, GoodJob, Resque, Delayed Job, rack-mini-profiler, ActiveAdmin, RailsAdmin) is reachable at a predictable path and returned a working page with framework-specific markers, not a login screen. These operator interfaces often ship without authentication.

**How it's exploited:** An attacker browses straight to the dashboard and reads or manipulates job queues and sensitive job arguments, SQL queries and timing traces, or full administrative CRUD over records - leaking internal data and allowing privileged state changes.

**Fix:** Require authentication and authorization on every dashboard and admin mount, or disable it in production.`

	ModuleConfirmation = "Confirmed when Rails dashboard endpoints return responses containing framework-specific UI markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "info-disclosure", "light"}
)
