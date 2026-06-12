package spring_jolokia_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-jolokia-exposure"
	ModuleName  = "Spring Jolokia Exposure"
	ModuleShort = "Detects exposed Jolokia JMX endpoints providing HTTP access to Java Management Extensions"
)

var (
	ModuleDesc = `**What it means:** An unauthenticated Jolokia endpoint is exposed, giving HTTP/JSON access to the application's JMX (Java Management Extensions) layer. The scanner confirmed this by requesting known Jolokia paths (such as /jolokia, /jolokia/list, /jolokia/version, and Spring Boot Actuator variants like /actuator/jolokia) and matching Jolokia-specific JSON markers (agent, agentId, protocol, and MBean listings), after fingerprinting a random 404 path and a sibling catch-all to suppress false positives. This is a serious misconfiguration because JMX often exposes internal runtime state and management operations to anyone who can reach the URL.

**How it's exploited:** An attacker reads JMX attributes to harvest configuration, credentials, and environment details, and enumerates registered MBeans via /jolokia/list to map management operations. Depending on the MBeans available and Jolokia's write/exec configuration, attackers can invoke dangerous MBean operations, alter logging or datasource settings, and in some setups chain MBean invocation into remote code execution.

**Fix:** Disable or remove the Jolokia endpoint in production, or restrict it behind authentication and network controls and turn off write/exec access.`

	ModuleConfirmation = "Confirmed when Jolokia endpoints return valid JSON responses with agent information or MBean data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
