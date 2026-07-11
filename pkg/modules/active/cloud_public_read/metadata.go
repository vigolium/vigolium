package cloud_public_read

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-public-read"
	ModuleName  = "Cloud Public Read"
	ModuleShort = "Detects publicly readable sensitive paths on cloud storage endpoints"
)

var (
	ModuleDesc = `**What it means:** A credential-free client reached a non-wildcard cloud-storage path. Listings are observations, sensitive-looking names are candidates, and actual secret, private-key, or database-dump content is a finding.

**How it's exploited:** An attacker anonymously lists or downloads private objects. Public media buckets and successful status codes alone do not prove exposure.

**Fix:** Remove public-read policies and require authentication or signed URLs for non-public objects.`

	ModuleConfirmation = "Observation for anonymous listing, candidate for sensitive-looking names, finding only for credential/private-key/database-dump content"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "info-disclosure", "sensitive-file", "moderate"}
)
