package aspnet_viewstate_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-aspnet-viewstate-detect"
	ModuleName  = "ASP.NET ViewState Detect"
	ModuleShort = "Detects ASP.NET ViewState issues including missing encryption, CSRF tokens, and large payloads"
)

var (
	ModuleDesc = `## Description
Passively analyzes ASP.NET ViewState in HTML responses for security issues.
Checks for unencrypted ViewState (plaintext base64), missing EventValidation,
missing RequestVerificationToken on postback forms (CSRF risk), and oversized
ViewState payloads that may carry sensitive data.

## Notes
- Passive only: does not send any HTTP requests
- Parses __VIEWSTATE from HTML form fields
- Base64-decodes ViewState to check for encryption envelope
- Flags ViewState > 4KB as potential sensitive data carrier
- Deduplicates by host to report once per target

## References
- https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.viewstateencryptionmode
- https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery_(CSRF)`

	ModuleConfirmation = "Confirmed when ViewState is present and lacks encryption or associated security tokens"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"aspnet", "misconfiguration", "session", "light"}
)
