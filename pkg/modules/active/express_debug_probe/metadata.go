package express_debug_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-debug-probe"
	ModuleName  = "Express Debug Probe"
	ModuleShort = "Triggers error responses in Express/NestJS apps to detect stack trace and debug info leakage"
)

var (
	ModuleDesc = `**What it means:** This Express.js or NestJS application returns verbose error responses that leak internal debug information. When the probe sent a request a real backend would error on (a random 404 path, a malformed JSON body, or a non-numeric value where a numeric path segment was expected), the response exposed a Node.js stack trace, an internal filesystem path, or a NODE_ENV configuration entry. This indicates the app is not running with production error handling, so detailed internals are disclosed to clients.

**How it's exploited:** An attacker triggers these error responses to harvest absolute server file paths, module and dependency layout (node_modules, app source directories), and runtime environment details. This maps the internal structure of the deployment and pinpoints code locations and library versions, making follow-up attacks such as path traversal, dependency-specific exploits, and source-code probing far more precise.

**Fix:** Run the application with NODE_ENV set to production and add a global error handler that returns generic error messages without stack traces, file paths, or environment details.`

	ModuleConfirmation = "Confirmed when an error response contains stack traces, file paths, or debug markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "info-disclosure", "moderate"}
)
