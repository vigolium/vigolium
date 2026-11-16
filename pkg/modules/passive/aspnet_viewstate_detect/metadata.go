package aspnet_viewstate_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-detect"
	ModuleName  = "ASP.NET ViewState Detect"
	ModuleShort = "Detects ASP.NET ViewState issues including a published machineKey, missing encryption, CSRF tokens, and large payloads"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET page's __VIEWSTATE is signed with a published machineKey, unencrypted, oversized, or posted without __EVENTVALIDATION or __RequestVerificationToken.

**How it's exploited:** A published key lets anyone forge ViewState, which the server deserializes: code execution. Unencrypted ViewState exposes state, missing EventValidation allows postback tampering, and a missing anti-forgery token suggests forgeable cross-site requests.

**Fix:** Replace any machineKey copied from documentation with fresh keys, enable ViewState encryption and MAC, keep EventValidation on, and add anti-forgery tokens.`

	ModuleConfirmation = "Confirmed when ViewState is present and lacks encryption or associated security tokens; a published-key finding is confirmed by recomputing the ViewState MAC under that key"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "session", "light"}
)
