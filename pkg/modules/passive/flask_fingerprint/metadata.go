package flask_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "flask-fingerprint"
	ModuleName  = "Flask Fingerprint"
	ModuleShort = "Identifies Flask/Werkzeug installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application is built on the Flask web framework and its Werkzeug WSGI toolkit, as shown by the Server header, a Flask signed session cookie, the Werkzeug interactive debugger, or Jinja2/Flask error tracebacks in responses. This is informational technology fingerprinting, not a vulnerability on its own, though a Werkzeug debugger left exposed in production is itself a serious risk.

**How it's exploited:** Knowing the exact framework lets an attacker narrow their attack surface and target Flask/Werkzeug-specific weaknesses, such as known Werkzeug or Jinja2 CVEs, server-side template injection, weak SECRET_KEY session forgery, and the Werkzeug debugger PIN bypass that can lead to remote code execution when the debugger is reachable.

**Fix:** Remove framework-identifying headers (set Server to a generic value), never run the Werkzeug debugger or debug mode in production, and disable detailed error tracebacks on internet-facing deployments.`

	ModuleConfirmation = "Confirmed when Flask/Werkzeug-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"flask", "python", "fingerprint", "light"}
)
