package spring_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-fingerprint"
	ModuleName  = "Spring Fingerprint"
	ModuleShort = "Identifies Spring Boot/Spring MVC applications from response headers, cookies, error pages, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The target was passively identified as a Spring Boot or Spring MVC application from signals such as the X-Application-Context header, a Whitelabel Error Page, a JSESSIONID cookie, Spring default error JSON, or a Server header revealing Tomcat or Jetty. Informational technology disclosure, not a vulnerability by itself.

**How it's exploited:** Knowing the framework lets an attacker focus on Spring-specific weaknesses - probing exposed Actuator endpoints (env, heapdump, mappings) and Spring4Shell-class binding flaws - and target only the relevant CVEs.

**Fix:** Suppress framework-revealing headers and replace default Spring error pages and login forms with generic custom responses.`

	ModuleConfirmation = "Confirmed when Spring-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"spring", "java", "fingerprint", "light"}
)
