package mass_assignment

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mass-assignment"
	ModuleName  = "Mass Assignment"
	ModuleShort = "Detects mass assignment / parameter pollution in JSON APIs"
)

var (
	ModuleDesc = `**What it means:** A JSON API binds client-supplied fields directly to its data model without an allow-list, so it accepted a privilege property (role, is_admin, permissions) the client should never control - a mass assignment flaw.

**How it's exploited:** An attacker adds an extra key like "role":"admin" to a create or update body and the server saves it, escalating privileges. Confirmed by injecting one privilege key and verifying the response changes and the key reflects back while a benign canary does not.

**Fix:** Bind only an explicit allow-list of permitted fields per endpoint and strip privilege properties from request bodies.`

	ModuleConfirmation = "Confirmed when injecting a privilege key materially changes the response and the key is reflected back due to the injection (not present in the un-injected baseline), while a benign canary key is not similarly reflected"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "api", "moderate"}
)
