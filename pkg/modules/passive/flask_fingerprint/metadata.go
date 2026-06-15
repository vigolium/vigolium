package flask_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-fingerprint"
	ModuleName  = "Flask Fingerprint"
	ModuleShort = "Identifies Flask/Werkzeug installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application runs the Flask framework and Werkzeug WSGI toolkit, shown by the Server header, a Flask signed session cookie, the Werkzeug debugger, or Jinja2/Flask tracebacks. Informational fingerprinting, though an exposed debugger is itself a serious risk.

**How it's exploited:** Knowing the framework lets an attacker target Flask/Werkzeug weaknesses: known CVEs, server-side template injection, weak SECRET_KEY session forgery, and the Werkzeug debugger PIN bypass that can lead to remote code execution when reachable.

**Fix:** Set Server to a generic value, never run the Werkzeug debugger or debug mode in production, and disable detailed tracebacks.`

	ModuleConfirmation = "Confirmed when Flask/Werkzeug-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"flask", "python", "fingerprint", "light"}
)
