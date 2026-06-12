package ws_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-injection"
	ModuleName  = "WebSocket Injection"
	ModuleShort = "Tests for injection vulnerabilities in parameters forwarded to WebSocket message processing"
)

var (
	ModuleDesc = `**What it means:** A request parameter whose name suggests WebSocket message handling (message, msg, data, payload, content, cmd, query, and similar) passes attacker input into a processing context without proper validation or output encoding. The application reflected an injection payload unencoded, returned a database error, echoed command output, or evaluated a template expression, indicating untrusted data reaches a sensitive sink.

**How it's exploited:** An attacker submits crafted values in these parameters to achieve cross-site scripting (running script in a victim's browser), SQL injection (reading or altering database contents), OS command injection (executing shell commands on the server), or server-side template injection (evaluating expressions that can lead to code execution). The concrete impact depends on which payload class the scanner confirmed for this parameter, ranging from session theft to data exfiltration or remote code execution.

**Fix:** Validate and contextually encode all parameter input on the server, use parameterized queries, never pass user input to shell or template evaluators, and apply the same controls to data forwarded into WebSocket message handling.`

	ModuleConfirmation = "Confirmed when an injected payload is reflected unencoded, triggers a SQL error, produces command output, or evaluates a template expression in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "moderate"}
)
