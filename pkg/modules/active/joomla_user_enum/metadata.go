package joomla_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-user-enum"
	ModuleName  = "Joomla User Enumeration"
	ModuleShort = "Detects Joomla user enumeration via registration form, API endpoints, and admin login exposure"
)

var (
	ModuleDesc = `**What it means:** Credential-free probes observed a Joomla registration form, structurally parsed public API user objects, or a marker-confirmed administrator login. These are distinct attack-surface features, not automatic enumeration flaws.

**How it's exploited:** Public user objects may aid reconnaissance, but a form or login page alone does not prove account creation, username-error differentials, private login identities, weak credentials, or administrative access.

**Fix:** Disable public registration if unneeded, tighten Web Services API permissions, and protect /administrator/ with IP allowlisting, a WAF, or HTTP auth.`

	ModuleConfirmation = "Observed only after grouped Joomla form/login markers or parsed users resources; no account creation, login weakness, or private identity is inferred"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"joomla", "php", "info-disclosure", "probe", "moderate"}
)
