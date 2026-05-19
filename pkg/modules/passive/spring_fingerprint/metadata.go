package spring_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-fingerprint"
	ModuleName  = "Spring Fingerprint"
	ModuleShort = "Identifies Spring Boot/Spring MVC applications from response headers, cookies, error pages, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Spring Boot and Spring MVC applications by analyzing HTTP
response headers (X-Application-Context, Server), cookies (JSESSIONID pattern),
default error page patterns (Whitelabel), and body content markers.

## Notes
- Passive only: does not send any HTTP requests
- Detects Spring via Whitelabel Error Page, server headers, session cookies
- Identifies underlying servlet container (Tomcat, Jetty, Undertow)
- Recognizes Spring-specific response patterns
- Deduplicates by host to avoid redundant processing

## References
- https://docs.spring.io/spring-boot/docs/current/reference/html/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server`

	ModuleConfirmation = "Confirmed when Spring-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"spring", "java", "fingerprint", "light"}
)
