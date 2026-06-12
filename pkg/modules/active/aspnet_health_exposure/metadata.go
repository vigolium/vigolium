package aspnet_health_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-health-exposure"
	ModuleName  = "ASP.NET Health Endpoint Exposure"
	ModuleShort = "Detects exposed ASP.NET health checks, monitoring dashboards, and metrics endpoints"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET Core health check, monitoring, or developer-tooling endpoint is reachable without authentication and returns operational detail it should not expose publicly. Depending on which endpoint responds this can include component health status (database, cache, external dependencies), Prometheus metrics, environment variables and runtime configuration, distributed-app topology, or development tooling left enabled in production.

**How it's exploited:** An attacker browses the disclosed endpoint to map internal infrastructure and dependencies, learn which backing services are degraded or unreachable, read environment configuration, and confirm the framework and deployment mode. This reconnaissance narrows attack surface and informs follow-on attacks; an exposed dashboard or environment endpoint can leak secrets or configuration directly. The module probes a fixed list of known paths, confirms each against a 404 fingerprint and content markers, and reports only those returning genuine health or monitoring data.

**Fix:** Require authentication on health, metrics, dashboard, and environment endpoints, restrict them to internal networks, and disable development tooling in production.`

	ModuleConfirmation = "Confirmed when health or monitoring endpoints return detailed infrastructure information without authentication"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
