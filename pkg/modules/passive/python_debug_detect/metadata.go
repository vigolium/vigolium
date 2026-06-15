package python_debug_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "python-debug-detect"
	ModuleName  = "Python Debug Detect"
	ModuleShort = "Detects Python tracebacks, debug pages, and path disclosure in responses"
)

var (
	ModuleDesc = `**What it means:** The application returned a Python debug surface, such as the Werkzeug debugger, a Django DEBUG=True page, a full traceback, or disclosed site-packages paths. In production these leak internal detail and, for Werkzeug, expose a live debug console.

**How it's exploited:** An attacker reads leaked tracebacks, settings, and source paths to map the codebase, and harvests inline secrets. If the Werkzeug console is reachable and its PIN absent, this escalates to remote code execution.

**Fix:** Disable debug mode in production (Flask app.debug=False / Django DEBUG=False), never ship the Werkzeug debugger, and return generic error pages.`

	ModuleConfirmation = "Confirmed when Python-specific debug patterns or tracebacks are found in response bodies"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"python", "info-disclosure", "misconfiguration", "light"}
)
