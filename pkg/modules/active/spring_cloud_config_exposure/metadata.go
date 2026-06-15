package spring_cloud_config_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-cloud-config-exposure"
	ModuleName  = "Spring Cloud Config Exposure"
	ModuleShort = "Detects exposed Spring Cloud Config Server endpoints leaking application configuration and secrets"
)

var (
	ModuleDesc = `**What it means:** A Spring Cloud Config Server is reachable without authentication and serves application configuration over HTTP. The scanner confirmed it via config paths (such as /application/default) returning propertySources JSON, which routinely expose database credentials, API keys, and internal service URLs.

**How it's exploited:** An attacker fetches the config endpoints for each environment profile and reads the property values, harvesting plaintext secrets and internal hostnames that grant direct access to databases and internal services.

**Fix:** Place the Config Server behind authentication, never expose it publicly, and store secrets in an encrypted vault rather than cleartext.`

	ModuleConfirmation = "Confirmed when config server endpoints return application configuration with property sources"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
