package spring_gateway_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-gateway-exposure"
	ModuleName  = "Spring Gateway Exposure"
	ModuleShort = "Detects exposed Spring Cloud Gateway actuator endpoints revealing routes and filters"
)

var (
	ModuleDesc = `## Description
Probes for exposed Spring Cloud Gateway actuator endpoints that reveal routing
configuration, global filters, and route filter definitions. Exposed gateway
routes can disclose internal service topology, backend URLs, and rate limiting
configuration. Write-enabled gateway endpoints could allow route manipulation
for traffic steering and SSRF-style attacks.

## Notes
- Runs once per host
- Checks gateway-specific actuator paths
- Validates responses using gateway JSON markers
- Read-only probing (does not attempt route modification)

## References
- https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#actuator-api
- https://cloud.spring.io/spring-cloud-gateway/reference/html/`

	ModuleConfirmation = "Confirmed when gateway actuator endpoints return route or filter configuration data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
