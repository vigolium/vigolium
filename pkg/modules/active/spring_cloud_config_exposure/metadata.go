package spring_cloud_config_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-cloud-config-exposure"
	ModuleName  = "Spring Cloud Config Exposure"
	ModuleShort = "Detects exposed Spring Cloud Config Server endpoints leaking application configuration and secrets"
)

var (
	ModuleDesc = `**What it means:** A Spring Cloud Config Server is reachable without authentication and serves application configuration over HTTP. The scanner confirmed this by requesting well-known config paths (such as /application/default, /application/prod, /application/dev, and branch-label variants) and getting back the server's propertySources JSON, or by hitting the /encrypt/status endpoint that confirms encryption is enabled. These responses routinely expose database credentials, API keys, encryption keys, and internal service URLs.
**How it's exploited:** An attacker simply fetches the config endpoints for each environment profile and reads the returned property values, harvesting plaintext secrets and internal hostnames that grant direct access to backing databases, third-party APIs, and other internal services, often enabling full lateral movement.
**Fix:** Place the Config Server behind authentication and network restrictions, never expose it publicly, and store secrets in an encrypted backend or vault rather than serving them in cleartext property sources.`

	ModuleConfirmation = "Confirmed when config server endpoints return application configuration with property sources"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
