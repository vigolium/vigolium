package python_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "python-debug-detect"
	ModuleName  = "Python Debug Detect"
	ModuleShort = "Detects Python tracebacks, debug pages, and path disclosure in responses"
)

var (
	ModuleDesc = `## Description
Passively detects Python tracebacks, debug information, and path disclosure in
HTTP responses. Identifies full Python tracebacks, file path disclosure via
site-packages paths, Django debug pages, and Werkzeug Debugger exposure. Each
detection pattern generates a separate finding with appropriate severity.

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host + detection type to avoid spam
- Werkzeug Debugger: Critical severity (potential RCE)
- Full Python traceback: High severity (secrets/paths exposed)
- Django debug page: High severity
- File path disclosure: Medium severity

## References
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when Python-specific debug patterns or tracebacks are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"python", "info-disclosure", "misconfiguration", "light"}
)
