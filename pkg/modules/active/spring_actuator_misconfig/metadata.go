package spring_actuator_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-actuator-misconfig"
	ModuleName  = "Spring Actuator Misconfiguration"
	ModuleShort = "Detects exposed Spring Boot actuator endpoints"
)

var (
	ModuleDesc = `**What it means:** A Spring Boot Actuator endpoint (such as /env, /info, /health, /metrics, /loggers, /beans, or /mappings) is reachable without authentication. These management endpoints are meant for operators only and expose internal application state, so unauthenticated access is a serious information-disclosure and attack-surface issue. The scanner confirms each hit by the endpoint's actuator-specific JSON structure (for example a status enum like UP for /health, the propertySources envelope for /env, or dotted Micrometer metric ids for /metrics), and rejects wildcard/soft-404 shells and sibling catch-all handlers to avoid false positives.

**How it's exploited:** An attacker reads /env or /beans to harvest environment variables, database credentials, API keys, internal hostnames, and the full configuration, then maps the application's routes via /mappings and its libraries via /info. Disclosed secrets and dependency versions enable lateral movement, and on misconfigured deployments writable actuator endpoints (for example /env or /loggers) can be chained into remote code execution.

**Fix:** Secure Actuator endpoints behind authentication and expose only /health publicly, restricting management endpoints via management.endpoints.web.exposure and network controls.`

	ModuleConfirmation = "Confirmed when an actuator path returns JSON matching that endpoint's specific actuator structure, the response is not the host's wildcard/soft-404 shell, and a guaranteed-nonexistent sibling under the same directory does not return the same content (ruling out catch-all handlers)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
