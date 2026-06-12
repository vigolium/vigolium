package backslash_transformation

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "backslash-transformation"
	ModuleName  = "Backslash Transformation Detection"
	ModuleShort = "Detects escape sequence interpretation, backslash consumption, character handling"
)

var (
	ModuleDesc = `**What it means:** A reflected parameter handles injected backslash escape sequences and special characters in a way that reveals server-side processing of the input. The scanner saw the server either strip backslashes, decode escape sequences (for example turning \x41 into A), or otherwise transform special characters such as quotes, braces, and command separators rather than echoing them literally. This is a probe-level signal that the value is parsed by an interpreter or backend, suggesting the parameter may be reachable by a deeper injection.

**How it's exploited:** This finding is reconnaissance, not a confirmed exploit. The observed transformation tells an attacker the input feeds an escape-aware parser and helps target follow-up tests for SQL injection, command injection, template injection, or escape-bypass attacks; backslash consumption in particular hints that escaping defenses can be neutralized. Confirmed impact depends on what that parser does with the decoded characters.

**Fix:** Treat untrusted input as literal data using context-appropriate parameterization or output encoding, and avoid unescaping or re-interpreting client-supplied escape sequences before use.`

	ModuleConfirmation = "Confirmed when injected backslash sequences are transformed differently than literal characters in the response"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "probe", "moderate"}
)
