package java_server_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-server-fingerprint"
	ModuleName  = "Java App-Server Fingerprint"
	ModuleShort = "Identifies Java app servers (Tomcat, Jetty, JBoss) from response headers and JSESSIONID cookies"
)

var (
	ModuleDesc = `**What it means:** The application's responses reveal that it runs on a Java application server (Apache Tomcat, Eclipse Jetty, JBoss, or a generic Servlet container), identified passively from the Server header, an X-Powered-By: Servlet header, or a JSESSIONID session cookie. This is an informational technology-fingerprint finding, not a vulnerability by itself, but disclosing the backend platform narrows the attack surface for an attacker.

**How it's exploited:** Knowing the target is a specific Java app server lets an attacker focus reconnaissance and select platform-specific exploits and known CVEs (for example Tomcat manager or AJP weaknesses, JBoss deserialization, or default management consoles), probe for default paths and admin endpoints, and tailor payloads instead of guessing the stack blindly.

**Fix:** Suppress or genericize version-revealing headers (Server, X-Powered-By) and avoid leaking the framework in cookie names where feasible, so the underlying server software is not advertised to unauthenticated clients.`

	ModuleConfirmation = "Confirmed when a Java app-server header or JSESSIONID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "fingerprint", "light"}
)
