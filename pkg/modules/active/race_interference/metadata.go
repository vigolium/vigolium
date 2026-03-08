package race_interference

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-race-interference"
	ModuleName  = "Race Interference Detection"
	ModuleShort = "Detects input storage, cross-contamination, and request interference races"
)

var (
	ModuleDesc = `## Description
Detects race condition vulnerabilities through parallel request analysis, looking for
input storage races, cross-request contamination, and request interference patterns.

## Notes
- Sends concurrent requests with different payloads and analyzes response variations
- Tests for TOCTOU and state mutation races
- Requires careful timing analysis

## References
- https://portswigger.net/research/smashing-the-state-machine`

	ModuleConfirmation = "Confirmed when parallel requests with different payloads produce cross-contaminated responses, indicating shared mutable state"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"race-condition", "heavy"}
)
