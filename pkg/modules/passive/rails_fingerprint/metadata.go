package rails_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-fingerprint"
	ModuleName  = "Rails Fingerprint"
	ModuleShort = "Identifies Ruby on Rails installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application reveals that it is built on Ruby on Rails. This module passively fingerprints Rails by observing tell-tale response signals: the X-Request-Id plus X-Runtime header pair, a Puma/Unicorn/Passenger Server header, a Rails _session cookie, or HTML markers such as the default 404/500 error pages, the CSRF meta tag, Turbo/Turbolinks attributes, or the Action Cable meta tag. This is informational technology disclosure, not a vulnerability by itself.

**How it's exploited:** Knowing the framework lets an attacker narrow attack-surface mapping and target Rails-specific weaknesses, for example deserialization and CVE chains in Rails, Devise, or the underlying gems, mass-assignment issues, and Action Cable or Active Storage endpoints. Default error pages and the X-Runtime timing header can further leak environment and response-time signals useful for tuning attacks.

**Fix:** Strip framework-identifying response headers (X-Runtime, X-Request-Id, Server) at the reverse proxy and replace default Rails error pages with generic custom pages.`

	ModuleConfirmation = "Confirmed when Rails-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "light"}
)
