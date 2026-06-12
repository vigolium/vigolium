package aspnet_viewstate_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-scan"
	ModuleName  = "ASP.NET ViewState Scan"
	ModuleShort = "Tests for ASP.NET ViewState MAC disabled, event validation bypass, and cookieless sessions"
)

var (
	ModuleDesc = `**What it means:** The scanner found one or more ASP.NET ViewState protection weaknesses on this site. The most serious is ViewState MAC disabled: the application accepted a tampered __VIEWSTATE (a byte-flipped, base64-encoded blob) without an integrity error, meaning EnableViewStateMac is off and the server-controlled state is no longer tamper-protected. The scanner may also report event validation disabled (a forged __EVENTTARGET accepted), verbose ViewState errors that leak stack traces, or cookieless session tokens embedded in URLs.

**How it's exploited:** With MAC validation off, an attacker can forge or modify ViewState; because ViewState is deserialized server-side, a crafted payload can lead to .NET deserialization and potentially remote code execution. Disabled event validation enables parameter tampering and invoking controls the page never exposed; stack traces aid further attacks; and cookieless session IDs in URLs leak via history, referrers, and logs, enabling session hijacking.

**Fix:** Enable EnableViewStateMac and EnableEventValidation, use cookie-based sessions, and disable verbose error pages in production.`

	ModuleConfirmation = "Confirmed when ViewState MAC is disabled (tampered ViewState accepted) or event validation can be bypassed"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "moderate"}
)
