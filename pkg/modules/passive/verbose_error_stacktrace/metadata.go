package verbose_error_stacktrace

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "verbose-error-stacktrace"
	ModuleName  = "Verbose Error Stack Trace"
	ModuleShort = "Detects full stack traces with file paths in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The application returned a full multi-line stack trace in an HTTP response, leaking internal file system paths, line numbers, and function or class names from the source code. This is an information-disclosure flaw caused by unhandled exceptions or debug mode being left on in a reachable environment.

**How it's exploited:** An attacker triggers errors and reads the trace to map the server's directory layout, source structure, framework, and language stack (Go, Java, Python, Node.js, .NET, Ruby, or PHP). That intelligence lets them target version-specific and framework-specific exploits, locate sensitive files, and craft more precise follow-on attacks such as path traversal, deserialization, or injection.

**Fix:** Disable debug and verbose error output in production, catch exceptions to return generic error pages, and log full stack traces server-side only.`

	ModuleConfirmation = "Confirmed when response body contains a structured stack trace with file paths and line numbers from a known technology stack"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
