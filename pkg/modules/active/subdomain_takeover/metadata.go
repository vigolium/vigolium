package subdomain_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-takeover"
	ModuleName  = "Subdomain Takeover"
	ModuleShort = "Detects dangling DNS records pointing to deprovisioned cloud services"
)

var (
	ModuleDesc = `**What it means:** A subdomain has a dangling DNS record (CNAME or A) pointing to a third-party cloud service that no longer hosts content for it, leaving the service slot unclaimed. The scanner confirmed this by requesting GET / and matching the response against known "unclaimed" fingerprints for providers such as GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, Netlify, and others, then verifying the host's CNAME actually points at that provider.
**How it's exploited:** An attacker registers the same service identifier (bucket, app, or page name) on that provider, immediately taking control of the live subdomain. From there they can serve malicious or phishing content under the trusted domain, steal cookies scoped to the parent domain, bypass CORS or CSP allowlists, and hijack OAuth or session flows that trust that origin.
**Fix:** Remove the stale DNS record, or reclaim the service identifier on the provider so the subdomain no longer resolves to an unclaimed slot.`
	ModuleConfirmation = "Confirmed when an HTTP response from the host matches known fingerprints of unclaimed/deprovisioned cloud service pages"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
