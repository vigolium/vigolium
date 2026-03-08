package aspnet_health_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-aspnet-health-exposure"
	ModuleName  = "ASP.NET Health Endpoint Exposure"
	ModuleShort = "Detects exposed ASP.NET health checks, monitoring dashboards, and metrics endpoints"
)

var (
	ModuleDesc = `## Description
Probes for exposed ASP.NET Core health check and monitoring endpoints that can
reveal infrastructure details including database connectivity status, external
service dependencies, memory and CPU metrics, and deployment configuration.
Covers standard health check endpoints, Health Checks UI dashboard, Prometheus
metrics, and development tooling left enabled in production.

## Notes
- Runs once per host
- Probes health check, monitoring, and dev-tooling endpoints
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages

## References
- https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/health-checks
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration`

	ModuleConfirmation = "Confirmed when health or monitoring endpoints return detailed infrastructure information without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
