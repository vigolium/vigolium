package spring_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-spring-debug-exposure"
	ModuleName  = "Spring Debug Exposure"
	ModuleShort = "Detects Spring Boot debug endpoints, Whitelabel error pages, and verbose stack trace disclosure"
)

var (
	ModuleDesc = `## Description
Probes for Spring Boot debug endpoints and verbose error page configurations.
Detects Whitelabel error pages with stack traces, Spring Boot DevTools remote
endpoints, and debug parameter behaviors that reveal internal application details
including package names, class paths, library versions, and configuration.

## Notes
- Runs once per host
- Checks Whitelabel error page with trace parameter
- Probes Spring Boot DevTools remote restart endpoint
- Tests for debug parameter behaviors
- Fingerprints 404 responses to reduce false positives

## References
- https://docs.spring.io/spring-boot/docs/current/reference/html/web.html#web.servlet.spring-mvc.error-handling
- https://docs.spring.io/spring-boot/docs/current/reference/html/using.html#using.devtools`

	ModuleConfirmation = "Confirmed when debug endpoints or verbose error pages reveal internal application details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
