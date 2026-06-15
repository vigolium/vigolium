package aspnet_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-sensitive-files"
	ModuleName  = "ASP.NET Sensitive Files"
	ModuleShort = "Probes for exposed ASP.NET configuration files, backups, and sensitive directories"
)

var (
	ModuleDesc = `**What it means:** The server returns ASP.NET sensitive files that should never be web-accessible (web.config and .bak/.old variants, appsettings.json, connectionStrings.config, Global.asax, App_Data and bin listings, crossdomain.xml). Hits are confirmed on a 200 with expected content markers, ruling out custom error pages.

**How it's exploited:** An attacker downloads these to harvest database connection strings, authentication and machine keys, and API secrets, or abuse a wildcard cross-domain policy to read authenticated responses cross-origin.

**Fix:** Block direct access to these paths and store configuration secrets outside the web root or in a secret manager.`

	ModuleConfirmation = "Confirmed when sensitive file paths return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"aspnet", "sensitive-file", "probe", "light"}
)
