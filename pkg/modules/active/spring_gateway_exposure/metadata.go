package spring_gateway_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-gateway-exposure"
	ModuleName  = "Spring Gateway Exposure"
	ModuleShort = "Detects exposed Spring Cloud Gateway actuator endpoints revealing routes and filters"
)

var (
	ModuleDesc = `**What it means:** A Spring Cloud Gateway actuator endpoint (/actuator/gateway/routes, /globalfilters, or /routefilters) is publicly reachable and returns gateway configuration. These endpoints expose internal routing rules, the backend service URLs each route forwards to, the predicates that match traffic, and the global/route filter chain, all of which are meant to stay internal.

**How it's exploited:** An attacker reads the route table to map the internal service topology and discover backend hostnames and ports (often non-public hosts), then crafts requests that hit those routes or feed reconnaissance for SSRF and lateral-movement attacks. The disclosed filter chain reveals which security, header-rewrite, and rate-limit filters are in place, helping an attacker find routes that lack auth and design bypasses. This module only reads the endpoints and does not attempt to modify any route.

**Fix:** Restrict the gateway actuator endpoints with authentication or network controls, or remove them from management.endpoints.web.exposure so they are not exposed to untrusted clients.`

	ModuleConfirmation = "Confirmed when gateway actuator endpoints return route or filter configuration data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
