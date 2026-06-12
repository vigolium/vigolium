package joomla_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-user-enum"
	ModuleName  = "Joomla User Enumeration"
	ModuleShort = "Detects Joomla user enumeration via registration form, API endpoints, and admin login exposure"
)

var (
	ModuleDesc = `**What it means:** This Joomla site exposes one or more user-facing surfaces that aid account enumeration or unauthorized access. The module confirms up to three issues with GET probes: a publicly reachable user registration form (/index.php?option=com_users&view=registration), the Joomla 4+ Web Services API returning user records anonymously at /api/index.php/v1/users, and an administrator login panel (/administrator/) reachable with no WAF, IP restriction, or other access control.

**How it's exploited:** An attacker harvests valid usernames from the API user listing or from registration-form error messages, then uses that list to target the exposed administrator login with credential-stuffing or brute-force attacks. Anonymous API user data also maps the site's account structure for further targeting.

**Fix:** Disable public registration if unneeded, require authentication and tighten Joomla Web Services API permissions so user records are not exposed anonymously, and protect /administrator/ with IP allowlisting, a WAF, or HTTP auth.`

	ModuleConfirmation = "Confirmed when user registration form is accessible, API exposes user data, or admin login is unprotected"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "info-disclosure", "probe", "moderate"}
)
