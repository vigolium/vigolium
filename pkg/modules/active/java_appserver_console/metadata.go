package java_appserver_console

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-appserver-console"
	ModuleName  = "Java App Server Console"
	ModuleShort = "Detects exposed admin consoles for WildFly/JBoss, WebLogic, and GlassFish/Payara"
)

var (
	ModuleDesc = `**What it means:** An administration console or management endpoint of an enterprise Java application server (WildFly/JBoss, Oracle WebLogic, GlassFish/Payara, or legacy JBoss JMX/web consoles) is reachable from outside. The scanner probes a fixed set of server-specific paths once per host and confirms a real console by matching product-specific HTML and header markers (against a per-host 404 fingerprint and anti-markers) on a 200 response. These consoles deploy applications and reconfigure the server, so exposing them widens the attack surface dramatically.

**How it's exploited:** An attacker who reaches an admin console tries default or weak credentials, or chains a known appserver CVE, to log in and deploy a malicious WAR or alter configuration for full server compromise. Unauthenticated surfaces are worse: the JBoss JMX console and JMXInvokerServlet (flagged Critical) allow direct MBean invocation and Java deserialization, which typically lead straight to remote code execution.

**Fix:** Restrict admin consoles and management endpoints to trusted networks, require strong authentication, and disable or remove legacy JMX/invoker servlets.`

	ModuleConfirmation = "Confirmed when app server admin console page or login form is accessible"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "tomcat", "info-disclosure", "probe", "light"}
)
