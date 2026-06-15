package java_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-sensitive-files"
	ModuleName  = "Java Sensitive Files"
	ModuleShort = "Detects Java-specific sensitive files: application configs, WEB-INF, META-INF, and build artifacts"
)

var (
	ModuleDesc = `**What it means:** A Java or Spring application file that should never be web-reachable is served to anonymous clients. The module probes known paths (WEB-INF/web.xml, META-INF/MANIFEST.MF, application.properties/yml, pom.xml, build.gradle) and reports only on a 200 carrying the file's expected content markers.

**How it's exploited:** Spring config files leak database credentials, API keys, and internal service URLs an attacker reads to pivot into back-end systems; web.xml, manifests, and build files disclose servlet mappings and dependency versions for targeting known CVEs.

**Fix:** Block these paths at the web server and keep WEB-INF/META-INF and config files out of any public document root.`

	ModuleConfirmation = "Confirmed when Java-specific sensitive files return expected structural content markers and survive a same-extension catch-all check"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"java", "sensitive-file", "probe", "light"}
)
