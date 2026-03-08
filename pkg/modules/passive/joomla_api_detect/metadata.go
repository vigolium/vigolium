package joomla_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-joomla-api-detect"
	ModuleName  = "Joomla API Exposure"
	ModuleShort = "Detects exposed Joomla Web Services API endpoints and CORS misconfigurations"
)

var (
	ModuleDesc = `## Description
Passively detects Joomla Web Services API (Joomla 4+) exposure by analyzing
response headers and bodies. Identifies application/vnd.api+json content types,
API resource links, and CORS headers on API responses that indicate endpoints
are accessible anonymously or with overly permissive cross-origin settings.

## Notes
- Passive only: does not send any HTTP requests
- Detects application/vnd.api+json content type
- Identifies /api/index.php path patterns
- Flags overly permissive CORS (Access-Control-Allow-Origin: *) on API endpoints
- Deduplicates by host

## References
- https://docs.joomla.org/J4.x:Joomla_Core_APIs
- https://developer.joomla.org/security-centre.html`

	ModuleConfirmation = "Confirmed when responses contain Joomla API content types or resource structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"joomla", "cms", "api", "light"}
)
