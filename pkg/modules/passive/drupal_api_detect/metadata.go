package drupal_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-api-detect"
	ModuleName  = "Drupal API Exposure"
	ModuleShort = "Detects exposed Drupal JSON:API and REST endpoints from response content"
)

var (
	ModuleDesc = `**What it means:** The site exposes a Drupal JSON:API or REST (HAL) endpoint that returns structured entity data, identified passively from response content types (application/vnd.api+json, application/hal+json), JSON:API/HAL body structures, or Drupal-specific headers. This is a low-severity informational fingerprint confirming a reachable Drupal API surface, not a vulnerability on its own.

**How it's exploited:** Knowing a Drupal data API is live lets an attacker map the attack surface and enumerate exposed entities, fields, and relationships through JSON:API collection and filter queries. If the endpoint is anonymously accessible and permissions are loose, this can surface user, node, or configuration data that should be restricted, and it confirms the CMS platform for version- and module-specific exploit targeting.

**Fix:** Restrict the JSON:API and REST module endpoints to authenticated, authorized roles (or disable them if unused), tighten entity and field access permissions, and avoid returning sensitive data to anonymous requests.`

	ModuleConfirmation = "Confirmed when responses contain JSON:API content types or Drupal REST entity data structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "cms", "api", "light"}
)
