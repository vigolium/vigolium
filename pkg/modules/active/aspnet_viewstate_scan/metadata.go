package aspnet_viewstate_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-scan"
	ModuleName  = "ASP.NET ViewState Scan"
	ModuleShort = "Tests for ASP.NET ViewState MAC disabled, event validation bypass, and cookieless sessions"
)

var (
	ModuleDesc = `**What it means:** The site has ASP.NET ViewState weaknesses. The most serious is ViewState MAC disabled: a tampered __VIEWSTATE was accepted without an integrity error, so EnableViewStateMac is off and server state is no longer tamper-protected. It may also flag disabled event validation or cookieless session tokens in URLs.

**How it's exploited:** With MAC off, an attacker forges ViewState; because it is deserialized server-side, a crafted payload can lead to .NET deserialization and remote code execution. Disabled event validation enables parameter tampering.

**Fix:** Enable EnableViewStateMac and EnableEventValidation, use cookie-based sessions, and disable verbose error pages in production.`

	ModuleConfirmation = "Confirmed when ViewState MAC is disabled (tampered ViewState accepted) or event validation can be bypassed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "moderate"}
)
