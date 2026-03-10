package error_message_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "error-message-detect"
	ModuleName  = "Error Message Detect"
	ModuleShort = "Detects interesting error messages in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects error messages in HTTP responses that reveal server-side technology,
debug information, or database error details. Covers debug pages, Apache, ASP.NET, Java,
Python, PHP, Ruby, Node.js, SQL database errors, and other common frameworks.

## Notes
- Categorizes errors by technology (Debug, Apache, ASP, Java, Generic, SQL)
- Debug page patterns are reported at low severity with certain confidence
- SQL error patterns are reported at low severity with firm confidence
- Other error patterns are reported at info severity with firm confidence

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- https://raw.githubusercontent.com/PortSwigger/error-message-checks/master/src/main/resources/burp/match-rules.tab
- https://github.com/1ndianl33t/Gf-Patterns`

	ModuleConfirmation = "Confirmed when response body contains recognizable error messages or stack traces from known frameworks"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"info-disclosure", "light"}
)
