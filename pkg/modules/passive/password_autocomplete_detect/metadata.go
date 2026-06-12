package password_autocomplete_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "password-autocomplete-detect"
	ModuleName  = "Password Autocomplete Detect"
	ModuleShort = "Detects password fields without autocomplete disabled"
)

var (
	ModuleDesc = `**What it means:** An HTML password input field in the response does not disable browser autocomplete (it lacks autocomplete="off" or autocomplete="new-password" on the input, and the enclosing form is not set to autocomplete="off"). This is a low-severity hardening gap: browsers and password managers may cache the typed credential, leaving it recoverable on the device.

**How it's exploited:** Anyone with later access to the same browser, such as a shared, kiosk, or stolen device, can retrieve cached credentials from the autofill store or have the browser re-populate the login form, or read them via local malware that scrapes the browser credential cache. There is no remote network exploit; impact depends on physical or local access to the client.

**Fix:** Add autocomplete="off" (or autocomplete="new-password" for password-change fields) to sensitive password inputs and their containing form so browsers do not store the credential.`

	ModuleConfirmation = "Confirmed when password input fields lack autocomplete='off' or autocomplete='new-password'"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"authentication", "misconfiguration", "light"}
)
