package laravel_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-misconfig"
	ModuleName  = "Laravel Misconfiguration"
	ModuleShort = "Detects Laravel debug mode, exposed debugbar, application logs, and configuration leaks"
)

var (
	ModuleDesc = `**What it means:** A Laravel application is exposing development and debugging features that should never be reachable in production. Depending on the probe that matched, this can be debug mode left on (Ignition or Whoops error pages), an open Debugbar, readable application or debug logs, an exposed Telescope or Horizon dashboard, or an environment file leaked through the storage symlink. These surfaces disclose stack traces, file paths, SQL queries, request data, and often the APP_KEY plus database, mail, and other environment credentials.

**How it's exploited:** An attacker reads the leaked internals to map the app and harvest secrets: logs and debug pages reveal stack traces and user data, Debugbar and Telescope expose queries, routes, and full request/response pairs, and a disclosed APP_KEY or .env yields signing keys and database or third-party credentials enabling session forgery or direct backend access. Some Ignition versions are also exploitable for RCE.

**Fix:** Set APP_DEBUG=false in production, remove or restrict Debugbar, Telescope, and Horizon, and block public access to storage, log, and environment files.`

	ModuleConfirmation = "Confirmed when probed Laravel endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "moderate"}
)
