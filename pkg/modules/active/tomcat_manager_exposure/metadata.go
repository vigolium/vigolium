package tomcat_manager_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-tomcat-manager-exposure"
	ModuleName  = "Tomcat Manager Exposure"
	ModuleShort = "Detects exposed Apache Tomcat Manager and Host Manager interfaces"
)

var (
	ModuleDesc = `## Description
Probes for exposed Apache Tomcat Manager and Host Manager web interfaces. These
administrative interfaces allow deploying WAR files, managing virtual hosts,
and viewing server status. Default or weak credentials on these interfaces
can lead to complete server compromise through malicious WAR deployment.

## Notes
- Runs once per host
- Checks manager, host-manager, and status pages
- Detects both login challenges (401 with WWW-Authenticate) and accessible pages
- Also detects Tomcat default pages and example servlets
- Fingerprints 404 responses to reduce false positives

## References
- https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html
- https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html`

	ModuleConfirmation = "Confirmed when Tomcat Manager or Host Manager interface is accessible or prompts for authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"tomcat", "java", "misconfiguration", "authentication", "light"}
)
