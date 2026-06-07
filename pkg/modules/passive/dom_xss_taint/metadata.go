package dom_xss_taint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-taint"
	ModuleName  = "DOM XSS (taint analysis)"
	ModuleShort = "Reports DOM XSS where a controllable source provably flows into a dangerous sink"
)

var (
	ModuleDesc = `## Description
Passively detects DOM-based XSS using AST taint analysis. Inline scripts and JavaScript
responses are parsed and a finding is raised only when the analyzer traces the *same data*
from a DOM-controlled source (location.hash, document.cookie, …) into a dangerous sink
(innerHTML, eval, document.write, …).

## Notes
- Higher precision than pattern matching: a source and a sink merely co-existing in a script
  is not enough; the data must flow from one to the other
- Complements the pattern-based dom-xss-detect module, which stays available
- Static analysis — not execution-confirmed; pair with the browser-confirming XSS modules
  for proof

## References
- https://owasp.org/www-community/attacks/DOM_Based_XSS`

	ModuleConfirmation = "Reported when AST taint analysis traces a DOM-controlled source into a dangerous sink within the same script"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "dom", "taint"}
)
