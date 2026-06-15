package angular_template_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "angular-template-injection"
	ModuleName  = "Angular Template Injection"
	ModuleShort = "Detects Angular template injection via expression evaluation"
)

var (
	ModuleDesc = `**What it means:** User input reaches an Angular (AngularJS) template and is evaluated as an expression instead of inert text. The scanner injected a math expression and saw the product returned (absent from baseline). This client-side template injection is equivalent to XSS.

**How it's exploited:** An attacker crafts an Angular payload with a constructor-chain sandbox bypass to run arbitrary JavaScript in victims' browsers - stealing cookies and tokens, hijacking accounts, and acting as the user.

**Fix:** Never interpolate untrusted input into Angular templates; treat user data as bound text and upgrade off sandbox-bypassable AngularJS versions.`

	ModuleConfirmation = "Confirmed when injected Angular math expressions are evaluated and the computed result appears in the response across multiple attempts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "injection", "ssti", "moderate"}
)
