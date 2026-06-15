package java_server_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-server-fingerprint"
	ModuleName  = "Java App-Server Fingerprint"
	ModuleShort = "Identifies Java app servers (Tomcat, Jetty, JBoss) from response headers and JSESSIONID cookies"
)

var (
	ModuleDesc = `**What it means:** Responses reveal a Java application server (Tomcat, Jetty, JBoss, or a generic Servlet container), identified passively from the Server header, an X-Powered-By: Servlet header, or a JSESSIONID cookie. Informational technology fingerprint, not a vulnerability, but it narrows the attack surface.

**How it's exploited:** Knowing the specific server lets an attacker focus recon and select platform CVEs (Tomcat manager or AJP, JBoss deserialization, default consoles), probe for default admin paths, and tailor payloads.

**Fix:** Suppress or genericize version-revealing headers (Server, X-Powered-By) and avoid leaking the framework in cookie names, so the server software is not advertised.`

	ModuleConfirmation = "Confirmed when a Java app-server header or JSESSIONID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "fingerprint", "light"}
)
