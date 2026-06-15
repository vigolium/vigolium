package spring_jolokia_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-jolokia-exposure"
	ModuleName  = "Spring Jolokia Exposure"
	ModuleShort = "Detects exposed Jolokia JMX endpoints providing HTTP access to Java Management Extensions"
)

var (
	ModuleDesc = `**What it means:** An unauthenticated Jolokia endpoint (/jolokia, /jolokia/list, /actuator/jolokia) gives HTTP/JSON access to the application's JMX layer, exposing internal runtime state and management operations to anyone who reaches the URL. Hits are confirmed by Jolokia-specific JSON markers.

**How it's exploited:** An attacker reads JMX attributes to harvest configuration, credentials, and environment details, and enumerates MBeans via /jolokia/list. Where write/exec is enabled, dangerous MBean operations can alter settings or chain into remote code execution.

**Fix:** Disable Jolokia in production, or restrict it behind authentication and network controls and turn off write/exec access.`

	ModuleConfirmation = "Confirmed when Jolokia endpoints return valid JSON responses with agent information or MBean data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
