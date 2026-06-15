package password_autocomplete_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "password-autocomplete-detect"
	ModuleName  = "Password Autocomplete Detect"
	ModuleShort = "Detects password fields without autocomplete disabled"
)

var (
	ModuleDesc = `**What it means:** An HTML password input does not disable browser autocomplete (it lacks autocomplete="off" or autocomplete="new-password", and its form is not set to autocomplete="off"). A low-severity hardening gap: browsers and password managers may cache the typed credential.

**How it's exploited:** Anyone with later access to the same browser (shared, kiosk, or stolen device) can retrieve cached credentials from the autofill store or have the browser re-populate the form. No remote exploit; impact depends on local access.

**Fix:** Add autocomplete="off" (or autocomplete="new-password" for change fields) to password inputs and their containing form so browsers do not store the credential.`

	ModuleConfirmation = "Confirmed when password input fields lack autocomplete='off' or autocomplete='new-password'"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"authentication", "misconfiguration", "light"}
)
