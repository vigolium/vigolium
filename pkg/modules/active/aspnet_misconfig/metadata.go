package aspnet_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-misconfig"
	ModuleName  = "ASP.NET Misconfiguration"
	ModuleShort = "Detects ASP.NET/IIS misconfigurations including exposed diagnostics, debug endpoints, and verbose errors"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET/IIS application is exposing a diagnostic, debug, or error-handling surface that should be disabled in production. The module probes well-known endpoints (trace.axd, elmah.axd, Glimpse, MiniProfiler, Hangfire dashboard, SignalR negotiate/hubs) and triggers a verbose Yellow Screen of Death error page, confirming each via response content markers after fingerprinting the site's 404 to rule out catch-all pages.

**How it's exploited:** Depending on what is exposed, an attacker reads request/response internals and logged errors (trace.axd, ELMAH), captured SQL queries and timing (MiniProfiler, Glimpse), or stack traces plus the exact .NET Framework version from a verbose error page, which maps internal paths, secrets in errors, and version-specific exploit targets. A publicly reachable Hangfire dashboard can let an attacker manipulate background jobs.

**Fix:** Disable or restrict diagnostic and debug endpoints in production, set customErrors to On (RemoteOnly) with a generic error page, and require authentication or IP allow-listing on any dashboard.`

	ModuleConfirmation = "Confirmed when diagnostic endpoints return 200 with expected content markers or verbose error information is disclosed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "info-disclosure", "light"}
)
