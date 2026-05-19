package spring_cloud_config_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-cloud-config-exposure"
	ModuleName  = "Spring Cloud Config Exposure"
	ModuleShort = "Detects exposed Spring Cloud Config Server endpoints leaking application configuration and secrets"
)

var (
	ModuleDesc = `## Description
Probes for exposed Spring Cloud Config Server endpoints that serve application
configuration for various environments. These endpoints can leak database
credentials, API keys, encryption keys, and internal service URLs. Also checks
for exposed encrypt/decrypt endpoints that could be abused for cryptographic
operations.

## Notes
- Runs once per host
- Checks common config patterns: /{app}/{profile} and /{app}/{profile}/{label}
- Probes encrypt and decrypt endpoints
- Validates responses using Spring Cloud Config JSON markers

## References
- https://docs.spring.io/spring-cloud-config/docs/current/reference/html/
- https://cloud.spring.io/spring-cloud-config/reference/html/#_security`

	ModuleConfirmation = "Confirmed when config server endpoints return application configuration with property sources"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
