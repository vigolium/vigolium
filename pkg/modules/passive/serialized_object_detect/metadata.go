package serialized_object_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "serialized-object-detect"
	ModuleName  = "Serialized Object Detection"
	ModuleShort = "Detects serialized Java/PHP/.NET/Python objects in request parameters"
)

var (
	ModuleDesc = `## Description
Passively detects serialized objects in HTTP request parameters by matching known
serialization format signatures for Java, PHP, .NET, and Python.

## Notes
- Java: base64 prefix "rO0AB" or hex prefix "aced0005"
- PHP: pattern matching O:N:"class", a:N:{, etc.
- .NET: base64 prefix "AAEAAAD" (BinaryFormatter)
- Python: pickle indicators ("ccopy_reg" prefix or protocol markers)

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests
- https://portswigger.net/web-security/deserialization`

	ModuleConfirmation = "Confirmed when request parameter values contain known serialization format signatures"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "light"}
)
