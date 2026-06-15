package backslash_transformation

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "backslash-transformation"
	ModuleName  = "Backslash Transformation Detection"
	ModuleShort = "Detects escape sequence interpretation, backslash consumption, character handling"
)

var (
	ModuleDesc = `**What it means:** A reflected parameter transforms injected backslash escapes and special characters, revealing server-side processing. The server stripped backslashes, decoded escape sequences (for example \x41 into A), or altered quotes rather than echoing them literally - a probe-level signal the value is parsed by an interpreter.

**How it's exploited:** This is reconnaissance, not a confirmed exploit. The transformation tells an attacker the input feeds an escape-aware parser, helping target follow-up tests for SQL, command, or template injection.

**Fix:** Treat untrusted input as literal data using parameterization or output encoding, and avoid unescaping client-supplied escape sequences before use.`

	ModuleConfirmation = "Confirmed when injected backslash sequences are transformed differently than literal characters in the response"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "probe", "moderate"}
)
