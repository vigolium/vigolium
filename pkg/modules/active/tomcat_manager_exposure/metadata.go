package tomcat_manager_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tomcat-manager-exposure"
	ModuleName  = "Tomcat Manager Exposure"
	ModuleShort = "Detects exposed Apache Tomcat Manager and Host Manager interfaces"
)

var (
	ModuleDesc = `**What it means:** An Apache Tomcat administrative or default endpoint is reachable from the network. The scanner probes /manager/html, /host-manager/html, /manager/status, /examples/, and /docs/, reporting a hit when the page returns 200 with its distinctive content or answers 401 with a Tomcat authentication challenge. These interfaces and leftover default apps should not be exposed and indicate incomplete hardening and an unnecessarily large attack surface.

**How it's exploited:** The Manager and Host Manager interfaces let an authenticated user deploy WAR files and manipulate virtual hosts, so an attacker who guesses default or weak credentials (for example tomcat/tomcat) can upload a malicious WAR for remote code execution and full server compromise. The status page leaks JVM, connector, and thread details, while the example servlets and docs disclose the server version and may carry known vulnerabilities, all aiding follow-up exploits.

**Fix:** Remove or restrict the Manager, Host Manager, examples, and docs applications, and require strong credentials over TLS plus network access controls for any administrative interface that must remain.`

	ModuleConfirmation = "Confirmed when Tomcat Manager or Host Manager interface is accessible or prompts for authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"tomcat", "java", "misconfiguration", "authentication", "light"}
)
