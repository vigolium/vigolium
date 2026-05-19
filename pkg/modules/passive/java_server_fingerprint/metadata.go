package java_server_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-server-fingerprint"
	ModuleName  = "Java App-Server Fingerprint"
	ModuleShort = "Identifies Java app servers (Tomcat, Jetty, JBoss) from response headers and JSESSIONID cookies"
)

var (
	ModuleDesc = `## Description
Passively identifies Java application servers (Apache Tomcat, Eclipse Jetty,
JBoss) via the Server header and the JSESSIONID session cookie. Complements
the Spring fingerprint by catching non-Spring Java deployments — raw
servlets, JSP apps, Struts, etc.

## Signals
- Server header containing "tomcat", "jetty", or "jboss"
- Set-Cookie: JSESSIONID=
- X-Powered-By: Servlet/<version>

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host
- Publishes "java" plus the specific server tag (e.g. "tomcat") to the tech registry`

	ModuleConfirmation = "Confirmed when a Java app-server header or JSESSIONID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "fingerprint", "light"}
)
