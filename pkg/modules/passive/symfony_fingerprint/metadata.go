package symfony_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-fingerprint"
	ModuleName  = "Symfony Fingerprint"
	ModuleShort = "Identifies Symfony PHP framework installations from headers, cookies, and debug profiler markers"
)

var (
	ModuleDesc = `**What it means:** The site runs the Symfony PHP framework, identified passively from an X-Powered-By: Symfony header, sf_redirect or MOCKSESSID cookies, or Profiler markers (/_wdt/, /_profiler/, X-Debug-Token). Informational recon; profiler markers also hint a debug configuration may be exposed.

**How it's exploited:** An attacker uses the disclosed framework and version hint to look up Symfony CVEs in routing, deserialization, or dependencies. A reachable Profiler can leak source paths, configuration, SQL queries, session data, and environment details.

**Fix:** Disable the Profiler and Web Debug Toolbar in production (set APP_ENV=prod), and strip X-Powered-By and X-Debug-Token at the app or reverse proxy.`

	ModuleConfirmation = "Confirmed when a Symfony header, cookie, or profiler marker is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"symfony", "php", "fingerprint", "light"}
)
