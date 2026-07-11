package drupal_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-user-enum"
	ModuleName  = "Drupal User Enumeration"
	ModuleShort = "Detects Drupal user enumeration via user profile paths and JSON:API"
)

var (
	ModuleDesc = `**What it means:** Credential-free controls found distinct Drupal public profile names through numeric routes or structurally parsed JSON:API user resources. Public profiles and author directories may be intentional.

**How it's exploited:** Profile names may aid password spraying only if they equal private login identities. This module does not prove that mapping, private-account disclosure, or weak login controls, so results remain observations.

**Fix:** Restrict anonymous access to user profiles and the JSON:API user resource (require auth or disable the module if unused), and avoid exposing usernames in profile URLs and titles.`

	ModuleConfirmation = "Observed when profile controls yield distinct non-catch-all names or parsed JSON:API contains user--user resources; login identity is not inferred"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "php", "info-disclosure", "probe", "moderate"}
)
