package aspnet_viewstate_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-viewstate-scan"
	ModuleName  = "ASP.NET ViewState Scan"
	ModuleShort = "Tests for ASP.NET ViewState MAC disabled, event validation bypass, and cookieless sessions"
)

var (
	ModuleDesc = `**What it means:** Valid and bit-flipped ViewState received equivalent WebForms processing while a malformed control failed, indicating a MAC candidate. Missing EventValidation is configuration evidence; cookieless session tokens are URL leakage.

**How it's exploited:** A missing MAC may permit forged serialized state, while disabled event validation can enable parameter tampering. Execution requires separate proof.

**Fix:** Enable ViewState MAC and event validation, use cookie-based sessions, and disable production error detail.`

	ModuleConfirmation = "ViewState integrity remains a candidate after valid/tampered/malformed differential controls; confirmation requires a semantic state effect. EventValidation absence is configuration evidence only"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "misconfiguration", "moderate"}
)
