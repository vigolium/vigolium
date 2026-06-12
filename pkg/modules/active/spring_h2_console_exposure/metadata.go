package spring_h2_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-h2-console-exposure"
	ModuleName  = "Spring H2 Console Exposure"
	ModuleShort = "Detects exposed H2 database web consoles commonly left enabled in Spring Boot applications"
)

var (
	ModuleDesc = `**What it means:** The application exposes the H2 database web console (at paths like /h2-console or /console) to unauthenticated users. This console is meant for local development only; reaching it in a deployed Spring Boot app means anyone on the network can open a full database administration interface.

**How it's exploited:** An attacker browses to the console, connects to the backing database, and runs arbitrary SQL to read, modify, or delete application data. Because H2 supports loading Java classes and aliasing functions through SQL, console access can often be escalated to remote code execution on the server, giving a complete host compromise.

**Fix:** Disable the H2 console in production (set spring.h2.console.enabled to false) or restrict it to localhost and require authentication; never ship the console reachable from untrusted networks.`

	ModuleConfirmation = "Confirmed when H2 console login page or interface is accessible without authentication"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "rce", "light"}
)
