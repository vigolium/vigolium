package jackson_deserialize_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jackson-deserialize-detect"
	ModuleName  = "Jackson Deserialization Detect"
	ModuleShort = "Detects Jackson polymorphic typing indicators and Java deserialization error patterns in responses"
)

var (
	ModuleDesc = `## Description
Passively detects indicators of Jackson polymorphic deserialization in HTTP
responses. Looks for type discriminator fields (@class, @type, java class
references) in JSON responses and Java deserialization error messages in
error responses. Jackson default typing can enable gadget-based RCE.

## Notes
- Passive only: does not send any HTTP requests
- Checks JSON responses for type discriminator fields
- Detects Java class references in JSON payloads
- Identifies deserialization error patterns
- Deduplicates by host

## References
- https://github.com/FasterXML/jackson-databind/wiki/Deserialization-Features
- https://cwe.mitre.org/data/definitions/502.html`

	ModuleConfirmation = "Confirmed when response contains Jackson type discriminator fields or Java deserialization error patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"java", "deserialization", "light"}
)
