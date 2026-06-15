package tomcat_manager_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tomcat-manager-exposure"
	ModuleName  = "Tomcat Manager Exposure"
	ModuleShort = "Detects exposed Apache Tomcat Manager and Host Manager interfaces"
)

var (
	ModuleDesc = `**What it means:** An Apache Tomcat administrative or default endpoint is reachable. The scanner probes the Manager, Host Manager, status, examples, and docs apps, flagging a 200 with distinctive content or a 401 auth challenge, and tries reverse-proxy path bypasses (e.g. /..;/manager/html).

**How it's exploited:** Manager and Host Manager let an authenticated user deploy WAR files, so an attacker with default credentials (tomcat/tomcat) can upload a malicious WAR for remote code execution and full server compromise.

**Fix:** Remove or restrict these apps, and require strong credentials over TLS plus network controls for any admin interface that must remain.`

	ModuleConfirmation = "Confirmed when Tomcat Manager or Host Manager interface is accessible or prompts for authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"tomcat", "java", "misconfiguration", "authentication", "light"}
)
