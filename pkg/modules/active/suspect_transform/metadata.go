package suspect_transform

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "suspect-transform"
	ModuleName  = "Suspect Transform Detection"
	ModuleShort = "Detects expression evaluation, quote consumption, unicode transformations"
)

var (
	ModuleDesc = `**What it means:** The server transformed an injected probe in a way the input alone does not explain, then reflected it back (confirmed twice). Such transforms are classic tells: arithmetic or template syntax evaluated (SSTI), quotes consumed, or unicode normalized (filter-bypass). A behavioral signal, not a confirmed bug.

**How it's exploited:** If markup is computed server-side, an attacker can escalate to SSTI or expression-language injection and often remote code execution. Quote consumption and unicode rewriting smuggle payloads past WAF blocklists.

**Fix:** Treat user input as inert data, never passing it into template or eval contexts, and validate after unicode normalization.`

	ModuleConfirmation = "Indicated when injected expressions are evaluated, quotes are consumed, or unicode characters are normalized by the server"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"behavior-analysis", "injection", "moderate"}
)
