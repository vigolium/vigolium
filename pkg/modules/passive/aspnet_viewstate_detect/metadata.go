package aspnet_viewstate_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-detect"
	ModuleName  = "ASP.NET ViewState Detect"
	ModuleShort = "Detects ASP.NET ViewState issues including missing encryption, CSRF tokens, and large payloads"
)

var (
	ModuleDesc = `**What it means:** This passive check found an ASP.NET page whose __VIEWSTATE field is configured insecurely. It reports up to four conditions: ViewState that is base64-encoded but not encrypted (so its serialized contents are readable by the client), an oversized ViewState over 4KB (which may carry more state than expected), a postback form missing __EVENTVALIDATION, and a postback form missing __RequestVerificationToken. These point to weak control over server-side state and form integrity, not a confirmed compromise.

**How it's exploited:** Unencrypted or large ViewState lets an attacker decode the base64 to inspect application state and any sensitive values stored there. Missing EventValidation allows tampering with postback parameters and control values the server assumes are fixed. A missing anti-forgery token suggests the form may accept cross-site forged requests, letting an attacker trigger actions in a victim's authenticated session.

**Fix:** Enable ViewState encryption and MAC, keep EventValidation on, store no secrets in ViewState, and add ASP.NET anti-forgery tokens to state-changing forms.`

	ModuleConfirmation = "Confirmed when ViewState is present and lacks encryption or associated security tokens"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "session", "light"}
)
