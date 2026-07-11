package mass_assignment

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mass-assignment"
	ModuleName  = "Mass Assignment"
	ModuleShort = "Detects mass assignment / parameter pollution in JSON APIs"
)

var (
	ModuleDesc = `**What it means:** A JSON API selectively accepted the exact typed value of a client-supplied privilege field. This is a candidate; two independent GET readbacks showing the same persisted value form a finding.

**How it's exploited:** An attacker adds a field such as "role":"admin" to a create or update request and the server persists it, escalating privileges.

**Fix:** Bind an explicit allowlist of fields per endpoint and reject client-supplied privilege properties.`

	ModuleConfirmation = "Candidate when the exact typed privilege value is selectively and repeatedly returned; confirmed only when two independent readbacks show the value persisted"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "api", "moderate"}
)
