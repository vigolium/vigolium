package python_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "python-debug-detect"
	ModuleName  = "Python Debug Detect"
	ModuleShort = "Detects Python tracebacks, debug pages, and path disclosure in responses"
)

var (
	ModuleDesc = `**What it means:** The application returned a Python debug or error surface in an HTTP response, such as the Werkzeug interactive debugger, a Django DEBUG=True page, a full Python traceback, or disclosed filesystem and dependency (site-packages) paths. These artifacts belong only in development; serving them in production leaks internal application detail and, in the Werkzeug case, exposes a live debug console.

**How it's exploited:** An attacker reads the leaked traceback, settings, environment variables, and source paths to map the codebase, framework versions, and installed packages for targeted follow-up attacks, and harvests any secrets shown inline. If the exposed Werkzeug debugger console is reachable (and its PIN is bypassed or absent), this escalates directly to remote code execution on the server.

**Fix:** Disable debug mode in production (Flask app.debug=False / Django DEBUG=False), never ship the Werkzeug debugger, and return generic error pages so tracebacks and paths are never sent to clients.`

	ModuleConfirmation = "Confirmed when Python-specific debug patterns or tracebacks are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"python", "info-disclosure", "misconfiguration", "light"}
)
