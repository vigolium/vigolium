package flask_werkzeug_debugger

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-werkzeug-debugger"
	ModuleName  = "Flask Werkzeug Debugger"
	ModuleShort = "Detects exposed Werkzeug interactive debugger enabling remote code execution"
)

var (
	ModuleDesc = `**What it means:** A Flask application runs with Werkzeug debug mode enabled. On an unhandled exception, Werkzeug renders an error page that can include a full interactive Python console (critical) or at least a stack trace exposing source paths.

**How it's exploited:** If the console is exposed, an attacker types Python into the in-browser debugger to run arbitrary code, read files, and pivot into the host. Even a leaked traceback hands over source paths and code internals.

**Fix:** Never run Werkzeug debug mode in production; set debug to false and serve behind a production WSGI server.`

	ModuleConfirmation = "Confirmed when error responses contain Werkzeug debugger markers indicating interactive console access"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"flask", "python", "rce", "misconfiguration", "light"}
)
