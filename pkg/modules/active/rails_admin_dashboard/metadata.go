package rails_admin_dashboard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-admin-dashboard"
	ModuleName  = "Rails Admin Dashboard"
	ModuleShort = "Detects exposed Rails ecosystem admin panels and dashboard UIs"
)

var (
	ModuleDesc = `## Description
Probes for common Rails ecosystem admin panels and background job dashboards that are
frequently mounted at predictable paths. Checks for Sidekiq, GoodJob, Resque, Delayed Job,
rack-mini-profiler, ActiveAdmin, and RailsAdmin.

## Notes
- Sends GET requests to known Rails dashboard paths
- Checks for framework-specific content markers in response bodies
- Reports both unauthenticated and auth-gated dashboards
- Fingerprints 404 responses to avoid false positives

## References
- https://github.com/sidekiq/sidekiq/wiki/Monitoring
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when Rails dashboard endpoints return responses containing framework-specific UI markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"rails", "ruby", "misconfiguration", "info-disclosure", "light"}
)
