package aspnet_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-misconfig"
	ModuleName  = "ASP.NET Misconfiguration"
	ModuleShort = "Detects ASP.NET/IIS misconfigurations including exposed diagnostics, debug endpoints, and verbose errors"
)

var (
	ModuleDesc = `## Description
Probes for exposed ASP.NET diagnostic and debug endpoints that should not be
accessible in production. Covers trace.axd, ELMAH, Glimpse, MiniProfiler,
Hangfire dashboard, SignalR endpoints, and Yellow Screen of Death (YSoD)
verbose error detection.

## Notes
- Runs once per host
- Probes diagnostic endpoints with content marker validation
- Tests for verbose error pages by triggering error conditions
- Fingerprints 404 to avoid false positives

## References
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration`

	ModuleConfirmation = "Confirmed when diagnostic endpoints return 200 with expected content markers or verbose error information is disclosed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "info-disclosure", "light"}
)
