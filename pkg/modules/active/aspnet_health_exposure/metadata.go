package aspnet_health_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-health-exposure"
	ModuleName  = "ASP.NET Health Endpoint Exposure"
	ModuleShort = "Detects exposed ASP.NET health checks, monitoring dashboards, and metrics endpoints"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET Core health check, monitoring, or dev-tooling endpoint is reachable without authentication and returns operational detail it should not expose - component health (database, cache, dependencies), Prometheus metrics, environment variables, or distributed-app topology.

**How it's exploited:** An attacker browses the endpoint to map internal infrastructure and dependencies, learn which backing services are degraded, and read environment config; an exposed dashboard can leak secrets directly. Hits are confirmed against a 404 fingerprint.

**Fix:** Require authentication on health, metrics, dashboard, and environment endpoints, restrict them to internal networks, and disable dev tooling in production.`

	ModuleConfirmation = "Confirmed when health or monitoring endpoints return detailed infrastructure information without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
