package subdomain_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-takeover"
	ModuleName  = "Subdomain Takeover"
	ModuleShort = "Detects dangling DNS records pointing to deprovisioned cloud services"
)

var (
	ModuleDesc = `**What it means:** A credential-free GET repeatedly matches a provider deprovisioning page. A strong candidate additionally requires the hostname's CNAME to end at that provider and an explicit unclaimed-resource fingerprint.

**How it's exploited:** If the provider namespace is actually claimable, an attacker may register it and serve content on the trusted subdomain. DNS errors and ambiguous unavailable-site pages remain observations; the scanner never registers the resource.

**Fix:** Remove the stale DNS record, or reclaim the service identifier so the subdomain no longer resolves to an unclaimed slot.`
	ModuleConfirmation = "Candidate requires provider-bound CNAME plus a strong deprovisioning fingerprint reproduced twice; claimability is not confirmed without registration"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
