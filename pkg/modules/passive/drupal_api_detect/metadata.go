package drupal_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-api-detect"
	ModuleName  = "Drupal API Exposure"
	ModuleShort = "Detects exposed Drupal JSON:API and REST endpoints from response content"
)

var (
	ModuleDesc = `## Description
Passively detects Drupal JSON:API and REST module exposure by analyzing response
headers and bodies. Identifies application/vnd.api+json content types, JSON:API
resource links, and REST module response patterns that indicate API endpoints
are accessible anonymously.

## Notes
- Passive only: does not send any HTTP requests
- Detects application/vnd.api+json content type (JSON:API)
- Identifies jsonapi resource links in response bodies
- Flags responses containing Drupal entity data structures
- Deduplicates by host

## References
- https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module
- https://www.drupal.org/docs/drupal-apis/restful-web-services-api`

	ModuleConfirmation = "Confirmed when responses contain JSON:API content types or Drupal REST entity data structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"drupal", "cms", "api", "light"}
)
