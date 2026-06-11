package serialized_object_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "serialized-object-detect"
	ModuleName  = "Serialized Object Detection"
	ModuleShort = "Detects serialized Java/PHP/.NET/Python/Ruby/Node.js objects in request parameters (incl. base64-wrapped)"
)

var (
	ModuleDesc = `## Description
Passively detects serialized objects in HTTP request parameters (query, path,
cookie, and body) by matching known serialization format signatures for Java,
PHP, .NET, Python, Ruby, and Node.js. Values are also re-checked after a single
base64-decode pass so that base64-wrapped payloads — the common transport form
in cookies and parameters — are caught.

## Notes
- Java: base64 prefix "rO0AB" or hex prefix "aced0005" or raw magic 0xAC 0xED
- PHP: pattern matching O:N:"class", a:N:{, etc.
- .NET: base64 prefix "AAEAAAD" (BinaryFormatter)
- Python: pickle indicators ("ccopy_reg" prefix or PROTO opcode 0x80 + version)
- Ruby: Marshal version header 0x04 0x08 (raw or base64-wrapped, e.g. "BAh...")
- Node.js: node-serialize function marker "_$$ND_FUNC$$_" (enables RCE on unserialize)
- Base64-wrapped payloads are flagged with a "(base64-wrapped)" format suffix

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests
- https://portswigger.net/web-security/deserialization`

	ModuleConfirmation = "Confirmed when request parameter values contain known serialization format signatures"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "light"}
)
