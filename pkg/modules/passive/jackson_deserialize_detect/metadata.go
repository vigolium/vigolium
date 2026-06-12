package jackson_deserialize_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jackson-deserialize-detect"
	ModuleName  = "Jackson Deserialization Detect"
	ModuleShort = "Detects Jackson polymorphic typing indicators and Java deserialization error patterns in responses"
)

var (
	ModuleDesc = `**What it means:** This passive check found signs that the application uses Jackson polymorphic (default) typing or exposes Java/Jackson deserialization errors. JSON responses carrying @class/@type type-discriminator fields, or response bodies leaking exceptions like JsonMappingException, InvalidTypeIdException, ObjectInputStream, or InvalidClassException, indicate the server may deserialize untrusted input into arbitrary Java types. This is a common precondition for deserialization vulnerabilities (CWE-502). The finding is a Tentative indicator from observed traffic only; it does not confirm that exploitation is possible.

**How it's exploited:** If Jackson default typing or unsafe Java deserialization is reachable on an input the attacker controls, they craft a payload naming a vulnerable gadget class, which the server instantiates during deserialization to achieve remote code execution or other impact. The leaked class names and error details also help map the framework and target known gadget chains.

**Fix:** Disable Jackson default typing (avoid enableDefaultTyping; use a strict allowlist via PolymorphicTypeValidator), avoid deserializing untrusted data into arbitrary types, and suppress stack traces and class details in responses.`

	ModuleConfirmation = "Confirmed when response contains Jackson type discriminator fields or Java deserialization error patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"java", "deserialization", "light"}
)
