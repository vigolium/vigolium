package jackson_deserialize_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jackson-deserialize-detect"
	ModuleName  = "Jackson Deserialization Detect"
	ModuleShort = "Detects Jackson polymorphic typing indicators and Java deserialization error patterns in responses"
)

var (
	ModuleDesc = `**What it means:** Passive signs the app uses Jackson polymorphic (default) typing or leaks Java deserialization errors. JSON @class/@type discriminator fields, or exceptions like JsonMappingException or InvalidTypeIdException, suggest the server may deserialize untrusted input into arbitrary Java types - a precondition for deserialization flaws (CWE-502). Tentative; not confirmed exploitable.

**How it's exploited:** If unsafe deserialization is reachable on attacker input, a payload naming a vulnerable gadget class is instantiated to achieve remote code execution.

**Fix:** Disable Jackson default typing (use a strict allowlist via PolymorphicTypeValidator), avoid deserializing untrusted data, and suppress stack traces.`

	ModuleConfirmation = "Confirmed when response contains Jackson type discriminator fields or Java deserialization error patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"java", "deserialization", "light"}
)
