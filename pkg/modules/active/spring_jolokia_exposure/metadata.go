package spring_jolokia_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-jolokia-exposure"
	ModuleName  = "Spring Jolokia Exposure"
	ModuleShort = "Detects exposed Jolokia JMX endpoints providing HTTP access to Java Management Extensions"
)

var (
	ModuleDesc = `## Description
Probes for exposed Jolokia endpoints that provide HTTP/JSON access to JMX
(Java Management Extensions). Jolokia can disclose sensitive runtime attributes,
MBean operations, and in some configurations enable dangerous operations like
remote code execution through MBean invocation.

## Notes
- Runs once per host
- Checks multiple Jolokia paths including actuator-prefixed variants
- Validates responses using Jolokia-specific JSON markers
- Fingerprints 404 responses to reduce false positives

## References
- https://jolokia.org/reference/html/index.html
- https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html`

	ModuleConfirmation = "Confirmed when Jolokia endpoints return valid JSON responses with agent information or MBean data"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
