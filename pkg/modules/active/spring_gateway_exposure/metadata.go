package spring_gateway_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-gateway-exposure"
	ModuleName  = "Spring Gateway Exposure"
	ModuleShort = "Detects exposed Spring Cloud Gateway actuator endpoints revealing routes and filters"
)

var (
	ModuleDesc = `**What it means:** A Spring Cloud Gateway actuator endpoint (/actuator/gateway/routes, /globalfilters, or /routefilters) is publicly reachable and returns gateway configuration, exposing internal routing rules, the backend service URLs each route forwards to, and the filter chain.

**How it's exploited:** An attacker reads the route table to map internal service topology and backend hostnames and ports (often non-public), then crafts requests against those routes or feeds reconnaissance for SSRF and lateral movement. The filter chain also reveals routes that lack auth.

**Fix:** Restrict the gateway actuator endpoints with authentication or network controls, or remove them from management.endpoints.web.exposure.`

	ModuleConfirmation = "Confirmed when gateway actuator endpoints return route or filter configuration data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
