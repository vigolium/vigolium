package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "smart-behavior-detection"
	ModuleName  = "Smart Behavior Detection"
	ModuleShort = "Diff-based injection detection via behavioral analysis"
)

var (
	ModuleDesc = `## Description
Detects injection vulnerabilities through differential response analysis. Sends pairs
of semantically equivalent and different payloads and compares response behaviors.

## Notes
- Uses behavioral diffing: true/false payload pairs that should produce identical vs different responses
- Low confidence; serves as a triage signal for deeper investigation

## References
- https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1571571c`

	ModuleConfirmation = "Indicated when semantically different payloads produce measurably different response behaviors while equivalent payloads produce identical responses"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"behavior-analysis", "injection", "moderate"}
)
