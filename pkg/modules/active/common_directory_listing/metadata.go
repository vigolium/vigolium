package common_directory_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-common-directory-listing"
	ModuleName  = "Common Directory Listing"
	ModuleShort = "Detects directory listing exposure on common web servers (Apache, Nginx, IIS, Jetty, Python)"
)

var (
	ModuleDesc = `## Description
Probes for directory listing exposure across common web servers including Apache,
Nginx, Microsoft IIS, Jetty, and Python SimpleHTTPServer. Directory listings reveal
the full file inventory of served directories, potentially exposing sensitive files,
backup archives, configuration files, and internal assets.

## Notes
- Runs once per host
- Probes common directories: /, /uploads/, /files/, /sites/, /assets/, /static/, /META-INF/, /WEB-INF/, /aspnet_client/, /App_Data/
- Detects Apache, Nginx, Python, Jetty, and IIS directory listing signatures
- Fingerprints 404 to avoid false positives on custom error pages

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
- https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html`

	ModuleConfirmation = "Confirmed when a directory path responds with server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
