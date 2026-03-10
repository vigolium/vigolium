package spring_h2_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-h2-console-exposure"
	ModuleName  = "Spring H2 Console Exposure"
	ModuleShort = "Detects exposed H2 database web consoles commonly left enabled in Spring Boot applications"
)

var (
	ModuleDesc = `## Description
Probes for exposed H2 database web consoles that are commonly enabled during
development and accidentally left accessible in production Spring Boot deployments.
The H2 console provides direct database access, enabling SQL execution, data
exfiltration, and potential remote code execution.

## Notes
- Runs once per host to avoid redundant probing
- Checks common H2 console paths with content markers
- Fingerprints 404 responses to reduce false positives
- H2 console exposure in production is critical severity

## References
- https://www.h2database.com/html/tutorial.html
- https://docs.spring.io/spring-boot/docs/current/reference/html/data.html#data.sql.h2-web-console`

	ModuleConfirmation = "Confirmed when H2 console login page or interface is accessible without authentication"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"spring", "java", "misconfiguration", "rce", "light"}
)
