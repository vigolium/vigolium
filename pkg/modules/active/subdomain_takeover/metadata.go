package subdomain_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-takeover"
	ModuleName  = "Subdomain Takeover"
	ModuleShort = "Detects dangling DNS records pointing to deprovisioned cloud services"
)

var (
	ModuleDesc = `**What it means:** A subdomain has a dangling DNS record (CNAME or A) pointing to a cloud service that no longer hosts content, leaving the slot unclaimed. Confirmed by matching GET / against unclaimed fingerprints for providers like GitHub Pages, Heroku, S3, and Netlify.

**How it's exploited:** An attacker registers the same service identifier (bucket, app, or page name) and immediately controls the live subdomain - serving phishing under the trusted domain, stealing parent-scoped cookies, and hijacking OAuth flows.

**Fix:** Remove the stale DNS record, or reclaim the service identifier so the subdomain no longer resolves to an unclaimed slot.`
	ModuleConfirmation = "Confirmed when an HTTP response from the host matches known fingerprints of unclaimed/deprovisioned cloud service pages"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
