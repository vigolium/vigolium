package flask_werkzeug_debugger

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-werkzeug-debugger"
	ModuleName  = "Flask Werkzeug Debugger"
	ModuleShort = "Detects exposed Werkzeug interactive debugger enabling remote code execution"
)

var (
	ModuleDesc = `**What it means:** A Flask application is running with Werkzeug's debug mode left enabled in a reachable environment. When an unhandled exception occurs, Werkzeug renders an error page that can include a full interactive Python console (critical) or, at minimum, a stack trace exposing source paths, file locations, and internal application structure (high). The scanner sends crafted requests to trigger 404 and 500 errors and confirms the response is a real Werkzeug error page, not a catch-all shell.

**How it's exploited:** If the interactive console is exposed, an attacker types Python directly into the in-browser debugger to run arbitrary code, read files, and pivot into the host, leading to full server compromise. Even when only a traceback is leaked, it hands the attacker source file paths, framework versions, and code internals that streamline targeting of further attacks.

**Fix:** Never run Flask or Werkzeug with debug mode enabled in production; set debug to false and serve behind a production WSGI server.`

	ModuleConfirmation = "Confirmed when error responses contain Werkzeug debugger markers indicating interactive console access"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"flask", "python", "rce", "misconfiguration", "light"}
)
