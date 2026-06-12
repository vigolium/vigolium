package symfony_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-fingerprint"
	ModuleName  = "Symfony Fingerprint"
	ModuleShort = "Identifies Symfony PHP framework installations from headers, cookies, and debug profiler markers"
)

var (
	ModuleDesc = `**What it means:** The response reveals that the site runs the Symfony PHP framework, identified passively from an X-Powered-By: Symfony header, sf_redirect or MOCKSESSID session cookies, or Symfony Web Debug Toolbar and Profiler markers (/_wdt/, /_profiler/, X-Debug-Token) in the response. This is informational, but disclosing the framework narrows the attack surface, and the X-Debug-Token header and profiler markers further suggest a development or debug configuration may be exposed in production.

**How it's exploited:** An attacker uses the disclosed framework and any version hint to look up Symfony-specific CVEs and target known weaknesses in routing, deserialization, or bundled dependencies. If the Web Debug Toolbar or Profiler is reachable, it can leak source paths, configuration, SQL queries, session data, and environment details that aid further exploitation.

**Fix:** Disable the Symfony Profiler and Web Debug Toolbar in production (ensure APP_ENV=prod and remove dev-only bundles), and strip framework-identifying headers such as X-Powered-By and X-Debug-Token at the application or reverse proxy.`

	ModuleConfirmation = "Confirmed when a Symfony header, cookie, or profiler marker is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"symfony", "php", "fingerprint", "light"}
)
