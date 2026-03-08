package java_appserver_console

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-java-appserver-console"
	ModuleName  = "Java App Server Console"
	ModuleShort = "Detects exposed admin consoles for WildFly/JBoss, WebLogic, and GlassFish/Payara"
)

var (
	ModuleDesc = `## Description
Probes for exposed administration consoles of enterprise Java application servers
including WildFly/JBoss, Oracle WebLogic, and GlassFish/Payara. These admin
consoles are high-value targets as they enable application deployment, server
configuration, and often have known CVEs. Default or weak credentials can lead
to full server compromise.

## Notes
- Runs once per host
- Checks server-specific admin console paths
- Detects both accessible consoles and authentication challenges
- Validates using server-specific HTML and header markers
- Fingerprints 404 responses to reduce false positives

## References
- https://docs.wildfly.org/
- https://docs.oracle.com/en/middleware/standalone/weblogic-server/
- https://glassfish.org/documentation`

	ModuleConfirmation = "Confirmed when app server admin console page or login form is accessible"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "tomcat", "info-disclosure", "probe", "light"}
)
