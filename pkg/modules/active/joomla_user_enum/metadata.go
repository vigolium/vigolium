package joomla_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-joomla-user-enum"
	ModuleName  = "Joomla User Enumeration"
	ModuleShort = "Detects Joomla user enumeration via registration form, API endpoints, and admin login exposure"
)

var (
	ModuleDesc = `## Description
Tests for Joomla user enumeration and admin exposure through multiple vectors:
1. Registration form: accessible /index.php?option=com_users&view=registration
2. Web Services API (J4+): /api/index.php/v1/users returns user data
3. Administrator login: /administrator/ publicly accessible without WAF/IP restrictions

## Notes
- Runs once per host
- Tests registration form accessibility and API user listing
- Checks administrator login exposure
- Non-destructive: only performs GET requests

## References
- https://docs.joomla.org/Security_Checklist
- https://developer.joomla.org/security-centre.html`

	ModuleConfirmation = "Confirmed when user registration form is accessible, API exposes user data, or admin login is unprotected"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "info-disclosure", "probe", "moderate"}
)
