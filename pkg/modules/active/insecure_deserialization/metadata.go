package insecure_deserialization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-deserialization"
	ModuleName  = "Insecure Deserialization"
	ModuleShort = "Detects insecure deserialization via error-based detection"
)

var (
	ModuleDesc = `**What it means:** An inert Java, PHP, Python, Ruby, or .NET wire-format probe reproducibly introduced a matching server-side deserialization exception while a plain malformed-value control stayed clean.

**How it's exploited:** Deserializer reachability is a high-priority candidate because a compatible gadget chain may lead to code execution or other impact. This module sends no gadget and does not label an exception as RCE; execution requires an OAST callback or safe side effect.

**Fix:** Never deserialize untrusted input; use safe formats like JSON with strict schemas, and if unavoidable enforce type allow-lists and payload integrity checks.`

	ModuleConfirmation = "Candidate requires a framework-matched error absent from baseline/control and reproduced by a second inert probe; findings require separate execution or side-effect proof"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "rce", "moderate"}
)
