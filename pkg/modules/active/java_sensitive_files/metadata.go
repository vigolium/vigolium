package java_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "java-sensitive-files"
	ModuleName  = "Java Sensitive Files"
	ModuleShort = "Detects Java-specific sensitive files: application configs, WEB-INF, META-INF, and build artifacts"
)

var (
	ModuleDesc = `## Description
Probes for Java/Spring-specific sensitive files not covered by generic file
discovery modules: application.properties/yml, WEB-INF/web.xml, META-INF
manifests, Maven/Gradle build files, and backup configuration files that
are commonly exposed through misconfigured static file serving.

## Notes
- Runs once per host
- Checks Java-specific config, deployment, and build artifact paths
- Validates responses with content markers and anti-markers
- Fingerprints 404 responses to detect custom error pages
- Complements the generic sensitive_file_discovery module

## References
- https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html
- https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html`

	ModuleConfirmation = "Confirmed when Java-specific sensitive files return expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "sensitive-file", "probe", "light"}
)
