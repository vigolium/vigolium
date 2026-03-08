package flask_werkzeug_debugger

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-werkzeug-debugger"
	ModuleName  = "Flask Werkzeug Debugger"
	ModuleShort = "Detects exposed Werkzeug interactive debugger enabling remote code execution"
)

var (
	ModuleDesc = `## Description
Detects exposed Werkzeug interactive debugger in Flask applications. The
Werkzeug debugger provides an interactive Python console in the browser when
an unhandled exception occurs. This allows arbitrary code execution on the
server and is a critical vulnerability when exposed in production.

## Notes
- Runs once per host to avoid redundant probing
- Sends requests designed to trigger 404 and 500 errors
- Distinguishes between full interactive debugger (critical/RCE) and stack trace disclosure (high/info disclosure)
- Interactive debugger confirmed by "Werkzeug Debugger" marker

## References
- https://flask.palletsprojects.com/en/latest/debugging/
- https://werkzeug.palletsprojects.com/en/latest/debug/`

	ModuleConfirmation = "Confirmed when error responses contain Werkzeug debugger markers indicating interactive console access"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"flask", "python", "rce", "misconfiguration", "light"}
)
