package subdomain_harvest

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-harvest"
	ModuleName  = "Subdomain Harvest"
	ModuleShort = "Collects in-scope subdomains referenced in HTML/JS responses for recon"
)

var (
	ModuleDesc = `**What it means:** This passive check reads HTML, JS, and JSON responses and collects every hostname sharing the page's registrable domain (eTLD+1), which SPAs and bundles routinely embed. It flags names suggesting non-production environments (dev, staging, test, qa). Informational recon, not a vulnerability.

**How it's exploited:** An organization's own subdomain list is high-value recon. Forgotten staging and dev hosts often run weaker auth, verbose errors, or stale code, letting an attacker pivot to the weakest host instead of the hardened primary one.

**Fix:** Ensure non-production and internal subdomains are not internet-reachable, not indexed, and absent from production bundles.`

	ModuleConfirmation = "Confirmed when one or more hostnames sharing the page's registrable domain are referenced in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"recon", "subdomain", "fingerprint", "light"}
)
