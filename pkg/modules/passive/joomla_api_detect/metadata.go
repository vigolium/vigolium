package joomla_api_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "joomla-api-detect"
	ModuleName  = "Joomla API Exposure"
	ModuleShort = "Detects exposed Joomla Web Services API endpoints and CORS misconfigurations"
)

var (
	ModuleDesc = `**What it means:** The target exposes the Joomla 4+ Web Services API, identified passively from a /api/index.php path returning a JSON:API response (application/vnd.api+json content type with links and data resource structures). This is primarily an informational fingerprint confirming the site runs Joomla and which REST API surface is reachable; if the same response also carries a wildcard CORS header (Access-Control-Allow-Origin: star), the finding is raised to Medium because any origin can read the API responses cross-site.

**How it's exploited:** Knowing the Joomla Web Services API is live lets an attacker map the REST attack surface, enumerate users, articles, and config endpoints, and target Joomla-version-specific CVEs against the API. With wildcard CORS, a malicious page in a victim browser can issue cross-origin reads and exfiltrate any data the victim's session can access through the API.

**Fix:** Restrict the Web Services API to trusted networks or authenticated tokens, disable it if unused, and never return Access-Control-Allow-Origin: star on API responses; allowlist specific trusted origins instead.`

	ModuleConfirmation = "Confirmed when responses contain Joomla API content types or resource structures"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"joomla", "cms", "api", "light"}
)
