package prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "prototype-pollution"
	ModuleName  = "Prototype Pollution"
	ModuleShort = "Detects server-side prototype pollution via JSON injection"
)

var (
	ModuleDesc = `**What it means:** The server handles __proto__ or constructor.prototype keys in a way that may mutate shared prototype state. Same-request behavior is a candidate; repeated effects in benign follow-ups, absent for a normal-property control, form a finding.

**How it's exploited:** An attacker pollutes inherited properties so later requests inherit attacker-controlled security or application values.

**Fix:** Reject __proto__ and constructor keys, and never recursively merge untrusted objects.`

	ModuleConfirmation = "Candidate for same-request special-key behavior; confirmed only when two benign follow-up requests retain an effect that a normal-property control did not"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "injection", "javascript", "moderate"}
)
