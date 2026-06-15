package java_appserver_console

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-appserver-console"
	ModuleName  = "Java App Server Console"
	ModuleShort = "Detects exposed admin consoles for WildFly/JBoss, WebLogic, and GlassFish/Payara"
)

var (
	ModuleDesc = `**What it means:** An admin console of an enterprise Java application server (WildFly/JBoss, WebLogic, GlassFish/Payara, or legacy JBoss JMX consoles) is reachable from outside, confirmed by matching product-specific markers against a per-host 404 fingerprint. These consoles deploy applications and reconfigure the server.

**How it's exploited:** An attacker tries default credentials or a known CVE to deploy a malicious WAR for full server compromise. Worse, the unauthenticated JBoss JMX console and JMXInvokerServlet (Critical) allow direct MBean invocation and Java deserialization, leading straight to remote code execution.

**Fix:** Restrict these endpoints to trusted networks, require authentication, and disable legacy JMX/invoker servlets.`

	ModuleConfirmation = "Confirmed when app server admin console page or login form is accessible"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "tomcat", "info-disclosure", "probe", "light"}
)
