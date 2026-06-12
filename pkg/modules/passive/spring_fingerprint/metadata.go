package spring_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-fingerprint"
	ModuleName  = "Spring Fingerprint"
	ModuleShort = "Identifies Spring Boot/Spring MVC applications from response headers, cookies, error pages, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The target was passively identified as a Spring Boot or Spring MVC application from telltale response signals such as the X-Application-Context header, a Whitelabel Error Page, a JSESSIONID cookie, a Spring Security login form, Spring Boot default error JSON (timestamp/status/error/path), or a Server/X-Powered-By header revealing Tomcat, Jetty, or Undertow. This is informational technology disclosure, not a vulnerability by itself, but it narrows the attack surface for an attacker.

**How it's exploited:** Knowing the framework and servlet container lets an attacker focus on Spring-specific weaknesses, for example probing for exposed Actuator endpoints (env, heapdump, mappings), Spring4Shell-class binding flaws, default Spring Security behaviors, and container-specific issues, and target only the CVEs that apply to the disclosed stack.

**Fix:** Suppress framework-revealing headers and replace default Spring error pages and login forms with generic custom responses to minimize fingerprinting.`

	ModuleConfirmation = "Confirmed when Spring-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"spring", "java", "fingerprint", "light"}
)
