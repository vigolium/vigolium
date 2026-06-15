package aspnet_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-misconfig"
	ModuleName  = "ASP.NET Misconfiguration"
	ModuleShort = "Detects ASP.NET/IIS misconfigurations including exposed diagnostics, debug endpoints, and verbose errors"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET/IIS application exposes a diagnostic, debug, or error-handling surface that should be disabled in production. The module probes well-known endpoints (trace.axd, elmah.axd, Glimpse, MiniProfiler, Hangfire) and triggers a verbose Yellow Screen of Death.

**How it's exploited:** An attacker reads logged errors and request internals (trace.axd, ELMAH), captured SQL (MiniProfiler, Glimpse), or stack traces and the .NET version from an error page, mapping internal paths and secrets. A reachable Hangfire dashboard lets an attacker manipulate jobs.

**Fix:** Disable diagnostic endpoints in production, set customErrors to On (RemoteOnly), and require authentication on dashboards.`

	ModuleConfirmation = "Confirmed when diagnostic endpoints return 200 with expected content markers or verbose error information is disclosed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "info-disclosure", "light"}
)
