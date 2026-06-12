package spring_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-debug-exposure"
	ModuleName  = "Spring Debug Exposure"
	ModuleShort = "Detects Spring Boot debug endpoints, Whitelabel error pages, and verbose stack trace disclosure"
)

var (
	ModuleDesc = `**What it means:** A Spring Boot application is exposing debug or diagnostic surface that should not be reachable in production. This module confirmed one or more of: the Whitelabel error page, full stack traces returned when a trace or message parameter is supplied, the DevTools remote restart endpoint, or actuator diagnostic endpoints (startup, conditions, scheduled tasks, caches). Each leaks internal application detail, and the DevTools restart endpoint is far more serious than a simple information leak.

**How it's exploited:** Stack traces and actuator output reveal package names, class paths, library versions, bean wiring, and scheduled-task method names, letting an attacker fingerprint dependencies to target version-specific exploits and map the internal attack surface. An exposed DevTools remote restart endpoint can let an attacker restart or reconfigure the application, and DevTools remote support has historically enabled remote code execution.

**Fix:** Disable DevTools in production, restrict actuator endpoints to authenticated internal access, and turn off the Whitelabel error page and stack-trace/message error attributes.`

	ModuleConfirmation = "Confirmed when debug endpoints or verbose error pages reveal internal application details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
