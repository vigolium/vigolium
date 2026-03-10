package directory_listing_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "directory-listing-detect"
	ModuleName  = "Directory Listing Detect"
	ModuleShort = "Passively detects directory listing exposure in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects directory listing exposure in HTTP responses across common web
servers including Apache, Nginx, Microsoft IIS, Jetty, and Python SimpleHTTPServer.

## Notes
- Analyzes existing responses without sending additional requests
- Detects Apache, Nginx, Python, Jetty, and IIS directory listing signatures
- Skips binary/media content types
- Only processes 2xx responses

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
- https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html`

	ModuleConfirmation = "Confirmed when response contains server-specific directory listing indicators such as Apache Index of, Nginx autoindex, IIS directory browsing, Jetty directory, or Python directory listing markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "misconfiguration", "directory-listing", "light"}
)
