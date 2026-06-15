package input_reflection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "input-reflection-detect"
	ModuleName  = "Input Reflection Detect"
	ModuleShort = "Detects request parameter values reflected in responses"
)

var (
	ModuleDesc = `**What it means:** A request parameter value was echoed back verbatim in the HTML response body. Informational: reflection alone is not a vulnerability, but it is a common prerequisite for reflected cross-site scripting (XSS), so the parameter is worth active testing.

**How it's exploited:** If the value is not output-encoded, an attacker crafts a parameter containing markup or script in a malicious link; when the victim loads it, the payload runs in their session. This confirms only the reflection point, not missing encoding.

**Fix:** Apply context-aware output encoding to every reflected parameter value, and validate input against an allowlist.`

	ModuleConfirmation = "Indicated when a request parameter value appears verbatim in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "injection", "light"}
)
