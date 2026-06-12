package suspect_transform

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "suspect-transform"
	ModuleName  = "Suspect Transform Detection"
	ModuleShort = "Detects expression evaluation, quote consumption, unicode transformations"
)

var (
	ModuleDesc = `**What it means:** The server transformed an injected probe in a way the input alone does not explain, and reflected the transformed result back (confirmed twice with randomized markers). These transformations are classic vulnerability tells: arithmetic or template/expression syntax being evaluated to its computed result (a server-side template injection or expression-language indicator), quotes being silently consumed (an injection-context indicator), or unicode being normalized, case-folded, byte-truncated, or rewritten via combining diacritics (filter-bypass indicators). This is a behavioral signal that input crosses an interpreter or normalizer, not a confirmed bug.

**How it's exploited:** If injected math or template markup is computed server-side, an attacker can escalate to full server-side template injection or expression-language injection and often to remote code execution. Quote consumption and unicode rewriting let an attacker smuggle payloads past input validation or WAF blocklists, reaching SQL, command, or template sinks that appeared protected.

**Fix:** Treat user input as inert data, never passing it into template, expression, or eval contexts, and validate input after any unicode normalization or decoding, not before.`

	ModuleConfirmation = "Indicated when injected expressions are evaluated, quotes are consumed, or unicode characters are normalized by the server"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"behavior-analysis", "injection", "moderate"}
)
