package lfi_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-lfi-generic"
	ModuleName  = "LFI Generic"
	ModuleShort = "Detects LFI via path traversal payloads"
)

var (
	ModuleDesc = `## Description
Detects Local File Inclusion vulnerabilities by injecting path traversal payloads
and checking for known file contents (e.g., /etc/passwd, win.ini) in responses.

## Notes
- Tests each insertion point with multiple traversal depth levels
- Matches against known OS file content signatures
- Uses request deduplication to avoid redundant checks

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion`

	ModuleConfirmation = "Confirmed when path traversal payloads cause known system file contents (e.g., /etc/passwd) to appear in the response"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"lfi", "injection", "moderate"}
)
