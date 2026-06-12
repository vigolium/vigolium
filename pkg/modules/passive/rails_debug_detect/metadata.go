package rails_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-debug-detect"
	ModuleName  = "Rails Debug Detect"
	ModuleShort = "Detects Rails debug exception pages, Better Errors, Web Console, and ActiveRecord errors in responses"
)

var (
	ModuleDesc = `**What it means:** A Ruby on Rails application is serving development or debug tooling in what should be a production response. The scanner passively matched markers for Rails detailed exception pages (ActionController/ActionView errors with backtraces), the Better Errors and Web Console development gems, leaked ActiveRecord database errors (PostgreSQL, MySQL, SQLite), or absolute Rails filesystem paths. These responses expose internal detail that should never reach end users; impact ranges from information disclosure up to remote code execution depending on which tooling is exposed.

**How it's exploited:** An attacker reads the leaked stack traces, source paths, gem versions, and database error text to map the codebase, schema, and table or column names for targeted SQL injection and exploit selection. If the Better Errors or Web Console interactive consoles are reachable, an attacker can run arbitrary Ruby on the server, achieving full remote code execution.

**Fix:** Remove the better_errors and web-console gems from production and configure Rails to return generic error pages with config.consider_all_requests_local set to false.`

	ModuleConfirmation = "Confirmed when Rails-specific debug patterns or exception details are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
