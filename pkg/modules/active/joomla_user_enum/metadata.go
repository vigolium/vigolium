package joomla_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-user-enum"
	ModuleName  = "Joomla User Enumeration"
	ModuleShort = "Detects Joomla user enumeration via registration form, API endpoints, and admin login exposure"
)

var (
	ModuleDesc = `**What it means:** This Joomla site exposes surfaces that aid account enumeration. GET probes confirm up to three issues: a public registration form, the Joomla 4+ Web Services API returning user records anonymously at /api/index.php/v1/users, and an administrator login panel (/administrator/) with no access control.

**How it's exploited:** An attacker harvests valid usernames from the API listing or registration-form errors, then targets the exposed administrator login with credential-stuffing or brute-force. Anonymous API data also maps the account structure.

**Fix:** Disable public registration if unneeded, tighten Web Services API permissions, and protect /administrator/ with IP allowlisting, a WAF, or HTTP auth.`

	ModuleConfirmation = "Confirmed when user registration form is accessible, API exposes user data, or admin login is unprotected"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "info-disclosure", "probe", "moderate"}
)
