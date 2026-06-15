package spring_h2_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-h2-console-exposure"
	ModuleName  = "Spring H2 Console Exposure"
	ModuleShort = "Detects exposed H2 database web consoles commonly left enabled in Spring Boot applications"
)

var (
	ModuleDesc = `**What it means:** The application exposes the H2 database web console (at paths like /h2-console or /console) to unauthenticated users. The console is for local development only; reaching it in a deployed app lets anyone on the network open a database administration interface.

**How it's exploited:** An attacker connects to the backing database and runs arbitrary SQL to read, modify, or delete data. Because H2 can load Java classes through SQL, console access is often escalated to remote code execution and host compromise.

**Fix:** Disable the H2 console in production (spring.h2.console.enabled to false) or restrict it to localhost with authentication.`

	ModuleConfirmation = "Confirmed when H2 console login page or interface is accessible without authentication"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "rce", "light"}
)
