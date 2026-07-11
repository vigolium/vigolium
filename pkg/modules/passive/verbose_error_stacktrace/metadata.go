package verbose_error_stacktrace

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "verbose-error-stacktrace"
	ModuleName  = "Verbose Error Stack Trace"
	ModuleShort = "Detects full stack traces with file paths in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The application returned a full multi-line stack trace, leaking internal file system paths, line numbers, and function or class names. This information-disclosure flaw comes from unhandled exceptions or debug mode left on.

**How it's exploited:** An attacker triggers errors and reads the trace to map the directory layout, framework, and language stack (Go, Java, Python, Node.js, .NET, Ruby, PHP), then targets version-specific exploits, locates sensitive files, and crafts follow-on attacks like path traversal or injection.

**Fix:** Disable debug and verbose errors in production, catch exceptions to return generic error pages, and log full stack traces server-side only.`

	ModuleConfirmation = "Candidate when a structured stack trace occurs in an HTTP error response; successful-response matches remain observations to account for documentation and examples"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
