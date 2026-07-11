package spring_h2_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-h2-console-exposure"
	ModuleName  = "Spring H2 Console Exposure"
	ModuleShort = "Detects exposed H2 database web consoles commonly left enabled in Spring Boot applications"
)

var (
	ModuleDesc = `**What it means:** An isolated credential-free request reached an H2-specific connection interface and passed soft-404, sibling, and marker-group controls. This is a dangerous development surface, not proof of database access.

**How it's exploited:** If separate credentials or permissive console settings allow a connection, an attacker may execute SQL and potentially abuse H2 capabilities. Login-page reachability alone proves neither authentication bypass nor code execution.

**Fix:** Disable the H2 console in production (spring.h2.console.enabled to false) or restrict it to localhost with authentication.`

	ModuleConfirmation = "Candidate requires credential-free 200 response with H2-specific marker groups and negative path controls; database or code execution is not tested"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "rce", "light"}
)
