package aspnet_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-sensitive-files"
	ModuleName  = "ASP.NET Sensitive Files"
	ModuleShort = "Probes for exposed ASP.NET configuration files, backups, and sensitive directories"
)

var (
	ModuleDesc = `**What it means:** The server returns the contents of ASP.NET-specific sensitive files or directories that should never be web-accessible. The module requests a fixed list of known paths (web.config and its .bak/.old/.Debug/.Release variants, appsettings.json and appsettings.Development.json, connectionStrings.config, Global.asax, classic ASP Global.asa and include files, the App_Data, bin and aspnet_client directory listings, packages.config and nuget.config, and the clientaccesspolicy.xml/crossdomain.xml policy files) and confirms each only when the response is HTTP 200 with the expected content markers, after fingerprinting a random 404 and applying anti-markers so custom error pages are not flagged. Cross-domain policy files are reported only when they contain an actual wildcard (uri=* / domain=*).

**How it's exploited:** An attacker downloads these files directly to harvest database connection strings, authentication keys, API secrets and machine keys from config files, list compiled assemblies from bin, or abuse a wildcard cross-domain policy to read authenticated responses cross-origin.

**Fix:** Block direct access to these paths and store configuration secrets outside the web root or in a secret manager.`

	ModuleConfirmation = "Confirmed when sensitive file paths return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "sensitive-file", "probe", "light"}
)
