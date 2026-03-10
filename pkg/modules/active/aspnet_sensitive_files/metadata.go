package aspnet_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-sensitive-files"
	ModuleName  = "ASP.NET Sensitive Files"
	ModuleShort = "Probes for exposed ASP.NET configuration files, backups, and sensitive directories"
)

var (
	ModuleDesc = `## Description
Discovers ASP.NET-specific sensitive files and directories exposed on the web
server. Covers web.config and its backups/transforms, appsettings.json files,
connection string configs, Global.asax, App_Data/bin directories, NuGet configs,
cross-domain policy files, and classic ASP include files.

## Notes
- Runs once per unique host
- Validates responses with content marker matching
- Fingerprints 404 responses to avoid false positives from custom error pages
- Anti-markers prevent false positives from HTML error pages

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/`

	ModuleConfirmation = "Confirmed when sensitive file paths return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "sensitive-file", "probe", "light"}
)
