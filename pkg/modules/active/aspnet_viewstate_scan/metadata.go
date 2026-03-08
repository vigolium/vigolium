package aspnet_viewstate_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-aspnet-viewstate-scan"
	ModuleName  = "ASP.NET ViewState Scan"
	ModuleShort = "Tests for ASP.NET ViewState MAC disabled, event validation bypass, and cookieless sessions"
)

var (
	ModuleDesc = `## Description
Actively tests ASP.NET ViewState security by tampering with ViewState MAC
validation, testing event validation bypass, detecting cookieless session
tokens in URLs, and checking for verbose error disclosure on ViewState
tampering.

## Notes
- Runs once per host
- Finds pages with __VIEWSTATE forms and tests MAC validation
- Tampers ViewState bytes and POSTs back to detect disabled MAC
- Submits forged __EVENTTARGET to detect disabled event validation
- Scans for cookieless session URL patterns (S(...)/)
- Checks if ViewState errors reveal stack traces

## References
- https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100)
- https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery_(CSRF)`

	ModuleConfirmation = "Confirmed when ViewState MAC is disabled (tampered ViewState accepted) or event validation can be bypassed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "moderate"}
)
