package rails_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-fingerprint"
	ModuleName  = "Rails Fingerprint"
	ModuleShort = "Identifies Ruby on Rails installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application reveals it is built on Ruby on Rails, fingerprinted passively via signals such as the X-Request-Id and X-Runtime headers, a Rails _session cookie, or HTML markers like default 404/500 pages and the CSRF meta tag. Informational technology disclosure, not a vulnerability.

**How it's exploited:** Knowing the framework lets an attacker target Rails-specific weaknesses: deserialization and CVE chains in Rails, Devise, or gems, mass-assignment, and Action Cable or Active Storage endpoints.

**Fix:** Strip framework-identifying headers (X-Runtime, X-Request-Id, Server) at the reverse proxy and replace default Rails error pages with generic custom pages.`

	ModuleConfirmation = "Confirmed when Rails-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "light"}
)
