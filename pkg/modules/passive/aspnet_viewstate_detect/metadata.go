package aspnet_viewstate_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-detect"
	ModuleName  = "ASP.NET ViewState Detect"
	ModuleShort = "Detects ASP.NET ViewState issues including missing encryption, CSRF tokens, and large payloads"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET page has an insecurely configured __VIEWSTATE: base64-encoded but not encrypted (contents client-readable), oversized (over 4KB), a postback form missing __EVENTVALIDATION, or missing __RequestVerificationToken. Signals weak control over server-side state and form integrity.

**How it's exploited:** Unencrypted ViewState can be decoded to inspect application state and secrets. Missing EventValidation allows tampering with postback parameters. A missing anti-forgery token suggests the form may accept cross-site forged requests in a victim's session.

**Fix:** Enable ViewState encryption and MAC, keep EventValidation on, store no secrets in ViewState, and add anti-forgery tokens to state-changing forms.`

	ModuleConfirmation = "Confirmed when ViewState is present and lacks encryption or associated security tokens"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "session", "light"}
)
