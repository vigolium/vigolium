package spring_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-debug-exposure"
	ModuleName  = "Spring Debug Exposure"
	ModuleShort = "Detects Spring Boot debug endpoints, Whitelabel error pages, and verbose stack trace disclosure"
)

var (
	ModuleDesc = `**What it means:** A Spring Boot application exposes debug surface that should not be reachable in production: the Whitelabel error page, full stack traces returned with a trace parameter, the DevTools remote restart endpoint, or actuator diagnostic endpoints (startup, conditions, caches).

**How it's exploited:** Stack traces and actuator output reveal package names, library versions, and bean wiring, letting an attacker fingerprint dependencies for version-specific exploits. An exposed DevTools restart endpoint can reconfigure the app and has enabled code execution.

**Fix:** Disable DevTools in production, restrict actuator endpoints to authenticated access, and turn off the Whitelabel error page and stack-trace attributes.`

	ModuleConfirmation = "Confirmed when debug endpoints or verbose error pages reveal internal application details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
