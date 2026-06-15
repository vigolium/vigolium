package ws_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-injection"
	ModuleName  = "WebSocket Injection"
	ModuleShort = "Tests for injection vulnerabilities in parameters forwarded to WebSocket message processing"
)

var (
	ModuleDesc = `**What it means:** A parameter named for WebSocket message handling (message, msg, data, payload, content, cmd, query) passes attacker input into a sink without validation. The scanner saw an unencoded reflection, a SQL error, command output, or an evaluated template expression.

**How it's exploited:** Crafted values achieve cross-site scripting, SQL injection, OS command injection, or server-side template injection. Impact depends on the confirmed payload class, from session theft to remote code execution.

**Fix:** Validate and contextually encode parameter input server-side, use parameterized queries, and never pass user input to shell or template evaluators.`

	ModuleConfirmation = "Confirmed when an injected payload is reflected unencoded, triggers a SQL error, produces command output, or evaluates a template expression in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "moderate"}
)
