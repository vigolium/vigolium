package llm_endpoint_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "llm-endpoint-fingerprint"
	ModuleName  = "LLM Endpoint Fingerprint"
	ModuleShort = "Identifies application-level LLM chat/completion endpoints"
)

var (
	ModuleDesc = `**What it means:** The endpoint is an application-level LLM chat/completion API (OpenAI-compatible messages/choices shape, or a prompt+generation-parameter body). This is informational — it marks the attack surface for prompt injection.

**How it's exploited:** LLM endpoints are the entry point for prompt injection, system-prompt leakage, and tool/agent abuse; identifying them lets the active prompt-injection probe target only real LLM surfaces.

**Fix:** Not a vulnerability by itself. Apply prompt-injection defenses (input/output filtering, privilege separation, no untrusted content in tool calls) on these endpoints.`

	ModuleConfirmation = "Identified by an LLM request/response body shape (messages+role, prompt+generation params, or a choices/delta completion object)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"llm", "ai", "fingerprint", "light"}
)
