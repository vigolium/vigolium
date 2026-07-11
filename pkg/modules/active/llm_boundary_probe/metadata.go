package llm_boundary_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "llm-boundary-probe"
	ModuleName  = "LLM Boundary Probe"
	ModuleShort = "Probes LLM endpoints for system-prompt / secret disclosure and tool abuse"
)

var (
	// ModuleDesc must contain the What/How/Fix markers and stay under 100 words.
	ModuleDesc = `**What it means:** The LLM endpoint can be steered by attacker-controlled input to reveal its confidential system prompt, configured credentials, or connection strings — a prompt-injection boundary failure.

**How it's exploited:** An attacker submits crafted instructions that override the system prompt and make the model print its initial instructions and any embedded API keys or secrets verbatim.

**Fix:** Never place secrets in prompts; keep credentials server-side. Add input/output filtering, privilege separation, and refuse requests to disclose system instructions.`

	ModuleConfirmation = "The identical credential/secret string is disclosed by two semantically-different disclosure prompts (cross-form agreement), ruling out model nondeterminism."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"llm", "ai", "prompt-injection", "heavy"}
)
