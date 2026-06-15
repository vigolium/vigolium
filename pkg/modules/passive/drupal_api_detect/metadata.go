package drupal_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-api-detect"
	ModuleName  = "Drupal API Exposure"
	ModuleShort = "Detects exposed Drupal JSON:API and REST endpoints from response content"
)

var (
	ModuleDesc = `**What it means:** The site exposes a Drupal JSON:API or REST (HAL) endpoint returning structured entity data, identified passively from response content types (application/vnd.api+json, application/hal+json). Informational recon confirming a reachable Drupal API surface, not a vulnerability itself.

**How it's exploited:** An attacker enumerates exposed entities, fields, and relationships via JSON:API collection and filter queries. If anonymously accessible with loose permissions, this can surface restricted user, node, or configuration data.

**Fix:** Restrict JSON:API and REST endpoints to authenticated roles (or disable if unused), tighten entity and field permissions, and avoid returning sensitive data to anonymous requests.`

	ModuleConfirmation = "Confirmed when responses contain JSON:API content types or Drupal REST entity data structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "cms", "api", "light"}
)
