package verbose_error_stacktrace

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "verbose-error-stacktrace"
	ModuleName  = "Verbose Error Stack Trace"
	ModuleShort = "Detects full stack traces with file paths in HTTP responses"
)

var (
	ModuleDesc = `## Description
Detects verbose stack traces in HTTP responses that expose internal file paths,
line numbers, and function names. Unlike the generic error-message-detect module,
this module specifically targets multi-line stack trace patterns with file system
paths, providing higher confidence findings for each technology stack.

Covers Go, Java, Python, Ruby, Node.js, .NET/C#, and PHP stack traces.

## Notes
- Uses multiline-aware regex patterns to detect structured stack traces
- Each technology stack has its own detection pattern and severity
- Requires at least one file path with line number to confirm a stack trace
- Deduplicates by host+path to avoid redundant findings

## References
- https://owasp.org/www-community/Improper_Error_Handling
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/209.html`

	ModuleConfirmation = "Confirmed when response body contains a structured stack trace with file paths and line numbers from a known technology stack"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
