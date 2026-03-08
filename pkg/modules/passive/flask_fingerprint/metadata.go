package flask_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-fingerprint"
	ModuleName  = "Flask Fingerprint"
	ModuleShort = "Identifies Flask/Werkzeug installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Flask/Werkzeug installations by analyzing HTTP response
headers (Server: Werkzeug), cookies (Flask default signed session cookie),
and body patterns (Werkzeug Debugger, Jinja2 errors, Flask tracebacks).
Reports with Certain confidence on strong signals, Firm on weak signals only.

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host to avoid redundant processing
- Strong signals: Werkzeug Debugger in body, Werkzeug in Server header
- Weak signals: Flask session cookie, Jinja2 errors, Flask tracebacks
- Requires 1+ strong signal or 2+ weak signals to report

## References
- https://flask.palletsprojects.com/`

	ModuleConfirmation = "Confirmed when Flask/Werkzeug-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"flask", "python", "fingerprint", "light"}
)
