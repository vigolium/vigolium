package suspect_transform

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-suspect-transform"
	ModuleName  = "Suspect Transform Detection"
	ModuleShort = "Detects expression evaluation, quote consumption, unicode transformations"
)

var (
	ModuleDesc = `## Description
Detects suspicious input transformations that may indicate vulnerabilities, including
expression evaluation, quote consumption, and unicode normalization issues.

## Notes
- Tests for server-side expression evaluation (math, string operations)
- Detects quote consumption that may indicate injection contexts
- Identifies unicode normalization that could bypass security filters

## References
- https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1571571c`

	ModuleConfirmation = "Indicated when injected expressions are evaluated, quotes are consumed, or unicode characters are normalized by the server"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"behavior-analysis", "injection", "moderate"}
)
