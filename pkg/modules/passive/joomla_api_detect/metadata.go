package joomla_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-api-detect"
	ModuleName  = "Joomla API Exposure"
	ModuleShort = "Detects exposed Joomla Web Services API endpoints and CORS misconfigurations"
)

var (
	ModuleDesc = `**What it means:** The target exposes the Joomla 4+ Web Services API, identified passively from /api/index.php returning a JSON:API response (application/vnd.api+json). Mainly an informational fingerprint of the reachable REST surface; a wildcard CORS header raises it to Medium, since any origin can read the API.

**How it's exploited:** A live API lets an attacker map the REST surface, enumerate users and config endpoints, and target Joomla-version CVEs. With wildcard CORS, a malicious page can read it cross-origin and exfiltrate session data.

**Fix:** Restrict the API to trusted networks or tokens, disable it if unused, and never return wildcard CORS.`

	ModuleConfirmation = "Confirmed when responses contain Joomla API content types or resource structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"joomla", "cms", "api", "light"}
)
