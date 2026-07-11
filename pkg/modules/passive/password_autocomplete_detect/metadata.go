package password_autocomplete_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "password-autocomplete-detect"
	ModuleName  = "Password Autocomplete Detect"
	ModuleShort = "Observes likely password fields without current-password or new-password semantics"
)

var (
	ModuleDesc = `**What it means:** A likely account-password field lacks autocomplete="current-password" or "new-password". This is a markup observation, not a confirmed vulnerability; browsers often infer the purpose, and autocomplete="off" is not a security control.

**How it's exploited:** Ambiguous semantics can make password-manager behavior less reliable, indirectly encouraging weaker credential handling rather than enabling a direct attack.

**Fix:** Use current-password for login fields and new-password for password creation or changes.`

	ModuleConfirmation = "Observed when a likely account-password input lacks current-password or new-password; this does not establish a security vulnerability"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"authentication", "misconfiguration", "light"}
)
