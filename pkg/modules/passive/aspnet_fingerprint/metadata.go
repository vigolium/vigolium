package aspnet_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-fingerprint"
	ModuleName  = "ASP.NET Fingerprint"
	ModuleShort = "Identifies ASP.NET and IIS installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies ASP.NET and Microsoft IIS installations by analyzing HTTP
response headers (X-AspNet-Version, X-AspNetMvc-Version, X-Powered-By, Server),
cookies (ASP.NET_SessionId, .ASPXAUTH, .AspNetCore.Cookies), and body patterns
(__VIEWSTATE, __EVENTVALIDATION, WebResource.axd, ScriptResource.axd).

## Notes
- Passive only: does not send any HTTP requests
- Extracts IIS version from Server header, ASP.NET version from X-AspNet-Version
- Detects classic ASP, ASP.NET Web Forms, ASP.NET MVC, and ASP.NET Core
- Deduplicates by host to avoid redundant processing

## References
- https://learn.microsoft.com/en-us/aspnet/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server`

	ModuleConfirmation = "Confirmed when ASP.NET-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"aspnet", "fingerprint", "light"}
)
