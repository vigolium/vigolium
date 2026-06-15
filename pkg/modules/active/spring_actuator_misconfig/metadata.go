package spring_actuator_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-actuator-misconfig"
	ModuleName  = "Spring Actuator Misconfiguration"
	ModuleShort = "Detects exposed Spring Boot actuator endpoints"
)

var (
	ModuleDesc = `**What it means:** Spring Boot Actuator endpoints (/env, /beans, /health, /metrics, /mappings, /loggers) are reachable without authentication, exposing internal application state meant only for operators.

**How it's exploited:** Attackers read /env or /beans to harvest environment variables, database credentials, API keys, and internal hostnames, then map routes via /mappings - enabling lateral movement, or remote code execution where endpoints are writable. Hits are confirmed by their actuator-specific JSON structure to rule out soft-404 shells.

**Fix:** Require authentication on Actuator, expose only /health publicly, and restrict management endpoints via management.endpoints.web.exposure and network controls.`

	ModuleConfirmation = "Confirmed when an actuator path returns JSON matching that endpoint's specific actuator structure, the response is not the host's wildcard/soft-404 shell, and a guaranteed-nonexistent sibling under the same directory does not return the same content (ruling out catch-all handlers)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
