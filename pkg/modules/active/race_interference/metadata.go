package race_interference

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "race-interference"
	ModuleName  = "Race Interference Detection"
	ModuleShort = "Detects input storage, cross-contamination, and request interference races"
)

var (
	ModuleDesc = `**What it means:** The application mishandles concurrent requests to this parameter. Sending parallel requests with tagged canaries, the scanner observed input storage (a value persisted into a later response), cross-contamination (a value from one request surfaced in another), or interference (parallel requests diverged from baseline). The first two are high-confidence.

**How it's exploited:** Overlapping requests exploit the lack of isolation: cross-contamination can leak one user's data, session tokens, or input into another's response, and storage races can poison shared caches.

**Fix:** Isolate per-request state and serialize access to shared resources with locks.`

	ModuleConfirmation = "Confirmed when parallel requests with different payloads produce cross-contaminated responses, indicating shared mutable state"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"race-condition", "heavy"}
)
