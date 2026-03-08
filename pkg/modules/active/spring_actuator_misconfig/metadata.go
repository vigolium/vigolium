package spring_actuator_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-spring-actuator-misconfig"
	ModuleName  = "Spring Actuator Misconfiguration"
	ModuleShort = "Detects exposed Spring Boot actuator endpoints"
)

var (
	ModuleDesc = `## Description
Detects exposed Spring Boot Actuator endpoints that leak sensitive application
information such as environment variables, health status, and configuration.

## Notes
- Checks common actuator paths (/actuator, /env, /health, /info, /mappings, etc.)
- Runs per-request to detect misconfigured access controls
- Exposed actuators can leak secrets, internal URLs, and database credentials

## References
- https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
- https://www.veracode.com/blog/research/exploiting-spring-boot-actuators`

	ModuleConfirmation = "Confirmed when actuator endpoints return valid JSON responses containing application configuration or health data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
