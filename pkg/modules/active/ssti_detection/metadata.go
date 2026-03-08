package ssti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-ssti-detection"
	ModuleName  = "SSTI Detection"
	ModuleShort = "Diff-based SSTI detection via error responses"
)

var (
	ModuleDesc = `## Description
Detects Server-Side Template Injection via Boolean Error-Based Blind technique.
Sends valid and invalid template expressions and compares response differences.

## Notes
- Uses differential analysis: valid template syntax vs invalid syntax
- Detects template engines by error response patterns
- Complements the Reflected SSTI module with blind detection

## References
- https://portswigger.net/research/server-side-template-injection`

	ModuleConfirmation = "Confirmed when valid template expressions produce different responses than syntactically invalid ones, indicating server-side evaluation"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"injection", "ssti", "moderate"}
)
