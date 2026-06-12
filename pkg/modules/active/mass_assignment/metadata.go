package mass_assignment

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mass-assignment"
	ModuleName  = "Mass Assignment"
	ModuleShort = "Detects mass assignment / parameter pollution in JSON APIs"
)

var (
	ModuleDesc = `**What it means:** A JSON API endpoint binds client-supplied fields directly to its internal data model without an allow-list, so it accepted a privilege-related property (such as role, admin, is_admin, permissions, or access_level) that the client should never control. This is a mass assignment / object property-level authorization flaw that lets users set fields the application assumed only it could set.

**How it's exploited:** An attacker adds an extra key like "role":"admin" or "is_admin":true to a normal create or update request body and the server saves it, allowing them to escalate their own privileges, flip account-verification or trust flags, or tamper with attributes the UI never exposes. The scanner confirms this by injecting one privilege key at a time, verifying the response materially changes and the injected key is reflected back while a benign canary key is not, so blindly mirroring or field-ignoring endpoints are not flagged.

**Fix:** Bind only an explicit allow-list of permitted fields per endpoint and reject or strip privilege-bearing properties from request bodies.`

	ModuleConfirmation = "Confirmed when injecting a privilege key materially changes the response and the key is reflected back due to the injection (not present in the un-injected baseline), while a benign canary key is not similarly reflected"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "api", "moderate"}
)
