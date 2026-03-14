package subdomain_takeover

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-takeover"
	ModuleName  = "Subdomain Takeover"
	ModuleShort = "Detects dangling DNS records pointing to deprovisioned cloud services"
)

var (
	ModuleDesc = `## Description
Detects subdomain takeover vulnerabilities caused by dangling DNS records (CNAME or A) pointing to
deprovisioned cloud services. When a service is removed but its DNS record remains, an attacker can
claim the same service identifier and serve malicious content under the target's domain.`
	ModuleConfirmation = "Confirmed when an HTTP response from the host matches known fingerprints of unclaimed/deprovisioned cloud service pages"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "misconfiguration", "moderate"}
)
