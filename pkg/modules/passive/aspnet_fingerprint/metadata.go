package aspnet_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-fingerprint"
	ModuleName  = "ASP.NET Fingerprint"
	ModuleShort = "Identifies ASP.NET and IIS installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application reveals that it runs on Microsoft IIS and/or the ASP.NET stack, and often the exact framework version, through response headers (X-AspNet-Version, X-AspNetMvc-Version, X-Powered-By, Server), session cookies (ASP.NET_SessionId, .ASPXAUTH, .AspNetCore.Cookies, ASPSESSIONID), and HTML body markers (__VIEWSTATE, __EVENTVALIDATION, WebResource.axd). This is an informational fingerprint, not a vulnerability on its own, but it leaks technology and version detail that should not be advertised.

**How it's exploited:** An attacker uses the disclosed platform and version to map attack surface and target known, version-specific weaknesses (for example padding-oracle and ViewState deserialization issues in vulnerable ASP.NET builds, or CVEs affecting a specific IIS release), skipping reconnaissance and going straight to applicable exploits.

**Fix:** Suppress version-disclosing headers (remove X-AspNet-Version, X-AspNetMvc-Version, X-Powered-By, and trim the Server banner) and keep the framework patched.`

	ModuleConfirmation = "Confirmed when ASP.NET-specific headers, cookies, or body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aspnet", "fingerprint", "light"}
)
