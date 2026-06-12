package race_interference

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "race-interference"
	ModuleName  = "Race Interference Detection"
	ModuleShort = "Detects input storage, cross-contamination, and request interference races"
)

var (
	ModuleDesc = `**What it means:** The application mishandles concurrent requests to this parameter. By sending many parallel requests carrying uniquely tagged canary values, the scanner observed one of three problems: input storage (a value persisted into a later response, a cache-poisoning signal), cross-contamination (a value from one concurrent request surfaced in another request's response, proving unsafe shared mutable state), or request interference (parallel requests diverged from the sequential baseline, suggesting a race over a shared resource). The first two are high-confidence; interference alone is a weaker, lower-severity signal.

**How it's exploited:** An attacker fires overlapping requests to exploit the lack of isolation: cross-contamination can leak one user's data, session tokens, or input into another user's response, and storage races can poison shared caches so malicious content is served to other users. Interference races can defeat check-then-act logic in payment, inventory, or privilege-change flows.

**Fix:** Isolate per-request state and serialize access to shared resources with atomic operations, transactions, or locks; never key cached or stored data on attacker-influenced concurrent input.`

	ModuleConfirmation = "Confirmed when parallel requests with different payloads produce cross-contaminated responses, indicating shared mutable state"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"race-condition", "heavy"}
)
