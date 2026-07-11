package race_interference

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "race-interference"
	ModuleName  = "Race Interference Detection"
	ModuleShort = "Detects input storage, cross-contamination, and request interference races"
)

var (
	ModuleDesc = `**What it means:** Parallel tagged GET requests showed repeatable input storage, same-session cross-contamination, or response divergence. Divergence is an observation; repeatable wrong-ID behavior is a candidate until cross-user or durable impact is proven.

**How it's exploited:** Concurrent requests may receive another operation's data or corrupt shared state, potentially crossing an authorization boundary.

**Fix:** Isolate per-request state and serialize access to shared mutable resources.`

	ModuleConfirmation = "Candidate when wrong-id behavior repeats with a fresh canary in one session; confirmed impact requires cross-user or durable state proof"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"race-condition", "heavy"}
)
