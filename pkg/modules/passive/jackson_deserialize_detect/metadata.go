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

	ModuleConfirmation = "Observation for parsed response-side type metadata or a single marker; candidate only for an error response with independent deserialization anchors; exploit confirmation requires an accepted attacker type and gadget side effect"
	// Precondition/lead only ("not confirmed exploitable"); the scanner tiers each
	// finding (Info for a leaked deser error, Low for @class/@type polymorphic
	// typing). Low is the ceiling — never Medium.
	ModuleSeverity   = severity.Low
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"java", "deserialization", "light"}
)
