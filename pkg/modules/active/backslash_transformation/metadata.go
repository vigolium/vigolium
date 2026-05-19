package backslash_transformation

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "backslash-transformation"
	ModuleName  = "Backslash Transformation Detection"
	ModuleShort = "Detects escape sequence interpretation, backslash consumption, character handling"
)

var (
	ModuleDesc = `## Description
Detects how servers handle backslash-escaped characters and special characters by injecting
escape sequences and analyzing transformations in the response.

## Notes
- Tests each insertion point for backslash consumption, escape interpretation, and unicode handling
- Useful as a precursor signal for deeper injection testing

## References
- https://portswigger.net/research/backslash-powered-scanning`

	ModuleConfirmation = "Confirmed when injected backslash sequences are transformed differently than literal characters in the response"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "probe", "moderate"}
)
