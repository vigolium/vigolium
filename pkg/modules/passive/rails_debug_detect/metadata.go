package rails_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-debug-detect"
	ModuleName  = "Rails Debug Detect"
	ModuleShort = "Detects Rails debug exception pages, Better Errors, Web Console, and ActiveRecord errors in responses"
)

var (
	ModuleDesc = `**What it means:** A Ruby on Rails app serves debug tooling in a production response. The scanner matched detailed exception pages, the Better Errors and Web Console gems, leaked ActiveRecord errors, or filesystem paths. Impact ranges from information disclosure to remote code execution.

**How it's exploited:** An attacker reads leaked stack traces and database errors to map the schema and column names for targeted SQL injection. If the Better Errors or Web Console consoles are reachable, they run arbitrary Ruby.

**Fix:** Remove the better_errors and web-console gems from production and set config.consider_all_requests_local to false so Rails returns generic error pages.`

	ModuleConfirmation = "Confirmed when Rails-specific debug patterns or exception details are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "info-disclosure", "misconfiguration", "light"}
)
