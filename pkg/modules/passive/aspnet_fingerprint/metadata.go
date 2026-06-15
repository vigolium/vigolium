package aspnet_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-fingerprint"
	ModuleName  = "ASP.NET Fingerprint"
	ModuleShort = "Identifies ASP.NET and IIS installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The target reveals it runs Microsoft IIS and/or the ASP.NET stack, often with the exact version, via headers (X-AspNet-Version, X-AspNetMvc-Version, X-Powered-By, Server), cookies (ASP.NET_SessionId, .ASPXAUTH, .AspNetCore.Cookies), and body markers (__VIEWSTATE, WebResource.axd). Informational fingerprint, not a vulnerability on its own.

**How it's exploited:** An attacker uses the disclosed platform and version to target known, version-specific weaknesses (padding-oracle and ViewState deserialization in vulnerable ASP.NET builds, or IIS CVEs) without reconnaissance.

**Fix:** Suppress version-disclosing headers (X-AspNet-Version, X-AspNetMvc-Version, X-Powered-By, and trim the Server banner) and keep the framework patched.`

	ModuleConfirmation = "Confirmed when ASP.NET-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aspnet", "fingerprint", "light"}
)
