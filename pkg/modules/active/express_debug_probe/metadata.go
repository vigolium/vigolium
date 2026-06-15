package express_debug_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-debug-probe"
	ModuleName  = "Express Debug Probe"
	ModuleShort = "Triggers error responses in Express/NestJS apps to detect stack trace and debug info leakage"
)

var (
	ModuleDesc = `**What it means:** This Express.js or NestJS app returns verbose error responses leaking internals. A request a real backend errors on (random 404, malformed JSON, non-numeric value in a numeric segment) exposed a Node.js stack trace, filesystem path, or NODE_ENV entry - production error handling is off.

**How it's exploited:** An attacker triggers these errors to harvest absolute file paths, dependency layout (node_modules), and library versions, making path traversal and dependency-specific exploits more precise.

**Fix:** Run with NODE_ENV set to production and add a global error handler returning generic messages without stack traces, file paths, or environment details.`

	ModuleConfirmation = "Confirmed when an error response contains stack traces, file paths, or debug markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "info-disclosure", "moderate"}
)
