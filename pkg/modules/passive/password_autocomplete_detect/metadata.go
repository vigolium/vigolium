package password_autocomplete_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "password-autocomplete-detect"
	ModuleName  = "Password Autocomplete Detect"
	ModuleShort = "Detects password fields without autocomplete disabled"
)

var (
	ModuleDesc = `## Description
Passively detects password input fields in HTML responses that do not have autocomplete
disabled, which may allow browsers to store sensitive credentials.

## Notes
- Checks for autocomplete="off" or autocomplete="new-password" on password inputs
- Also checks enclosing form elements for autocomplete attributes
- Only fires on text/html responses

## References
- https://owasp.org/www-community/controls/PasswordAutocomplete
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when password input fields lack autocomplete='off' or autocomplete='new-password'"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"authentication", "misconfiguration", "light"}
)
