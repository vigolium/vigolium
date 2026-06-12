package input_reflection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "input-reflection-detect"
	ModuleName  = "Input Reflection Detect"
	ModuleShort = "Detects request parameter values reflected in responses"
)

var (
	ModuleDesc = `**What it means:** A request parameter value was found echoed back verbatim in the HTML response body. This is informational: reflection by itself is not a vulnerability, but it is a common prerequisite for reflected cross-site scripting (XSS) and other injection flaws, so the parameter is worth manual or active testing.

**How it's exploited:** If the reflected value is not properly output-encoded for its HTML context, an attacker can craft a parameter containing markup or script (for example a script tag or an event handler) and deliver a malicious link to a victim. When the victim loads it, the injected payload renders in their browser session, enabling session theft, credential phishing, or actions performed as the victim. This finding only confirms the reflection point exists; it does not confirm that encoding is missing.

**Fix:** Apply context-aware output encoding to every parameter value reflected into a response, and validate input against an allowlist where feasible.`

	ModuleConfirmation = "Indicated when a request parameter value appears verbatim in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "injection", "light"}
)
