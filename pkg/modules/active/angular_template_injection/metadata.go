package angular_template_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "angular-template-injection"
	ModuleName  = "Angular Template Injection"
	ModuleShort = "Detects Angular template injection via expression evaluation"
)

var (
	ModuleDesc = `**What it means:** User-supplied input reaches an Angular (AngularJS) template where it is evaluated as an expression rather than rendered as inert text. The scanner injected an Angular expression such as the multiplication of two random numbers and saw the computed product reflected in the response (and absent from the baseline), proving the Angular engine is running attacker-controlled expressions. This is a client-side template injection flaw that breaks out of the template sandbox and is functionally equivalent to cross-site scripting.

**How it's exploited:** An attacker crafts an Angular expression payload, including the constructor-chain sandbox bypass this module also probes, to escape the expression sandbox and run arbitrary JavaScript in victims' browsers. That enables stealing session cookies and tokens, hijacking accounts, performing actions as the user, and defacing or redirecting the page.

**Fix:** Never interpolate untrusted input into Angular templates or expressions; treat user data as bound text/values only (one-time binding, strict contextual escaping) and upgrade off unsupported AngularJS versions whose sandbox is known-bypassable.`

	ModuleConfirmation = "Confirmed when injected Angular math expressions are evaluated and the computed result appears in the response across multiple attempts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "injection", "ssti", "moderate"}
)
