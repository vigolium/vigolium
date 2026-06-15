package laravel_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-misconfig"
	ModuleName  = "Laravel Misconfiguration"
	ModuleShort = "Detects Laravel debug mode, exposed debugbar, application logs, and configuration leaks"
)

var (
	ModuleDesc = `**What it means:** A Laravel app exposes development features that should never reach production: debug mode (Ignition or Whoops), an open Debugbar, readable logs, a Telescope or Horizon dashboard, or a leaked .env disclosing stack traces and often the APP_KEY plus database credentials.

**How it's exploited:** Debugbar and Telescope expose queries and full request/response pairs, and a disclosed APP_KEY or .env yields signing keys enabling session forgery or backend access. Some Ignition versions are exploitable for RCE.

**Fix:** Set APP_DEBUG=false in production, remove or restrict Debugbar, Telescope, and Horizon, and block public access to storage, log, and environment files.`

	ModuleConfirmation = "Confirmed when probed Laravel endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "moderate"}
)
