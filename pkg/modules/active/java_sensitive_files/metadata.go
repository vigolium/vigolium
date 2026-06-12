package java_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-sensitive-files"
	ModuleName  = "Java Sensitive Files"
	ModuleShort = "Detects Java-specific sensitive files: application configs, WEB-INF, META-INF, and build artifacts"
)

var (
	ModuleDesc = `**What it means:** A Java or Spring application file that should never be web-reachable is being served directly to anonymous clients. The module confirms this by requesting known paths (WEB-INF/web.xml, META-INF/MANIFEST.MF and the Maven directory, application.properties / application.yml / application.yaml and their prod and dev variants, bootstrap.properties / bootstrap.yml, pom.xml, build.gradle) and only reports when the response is a real 200 whose body carries the file's expected content markers, distinct from the host's 404 fingerprint.

**How it's exploited:** Spring config files commonly leak database credentials, API keys, and internal service URLs, which an attacker reads straight from the response to pivot into back-end systems; web.xml, manifests, and build files disclose servlet mappings, dependency versions, and build internals that let an attacker map the attack surface and target known framework CVEs.

**Fix:** Block all of these paths at the web server or proxy and ensure WEB-INF/META-INF and config files are never placed under a public document root.`

	ModuleConfirmation = "Confirmed when Java-specific sensitive files return expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "sensitive-file", "probe", "light"}
)
