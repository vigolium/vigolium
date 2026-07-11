package ssr_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-data-exposure"
	ModuleName  = "SSR Data Exposure"
	ModuleShort = "Detects sensitive data leaked in server-side rendered state blobs"
)

var (
	ModuleDesc = `**What it means:** A framework serialized security-relevant data into client-visible hydration state. Routine identity/role data, internal addresses, and public credential identifiers are observations. Substantive private-token formats, hashes, or password-bearing service URLs are candidates.

**How it's exploited:** Anyone viewing the page source (no authentication) reads the leaked values - API keys, AWS keys, connection strings, internal IPs, emails, password hashes, or admin flags - then replays them against the relevant service.

**Fix:** Strip secrets, credentials, and internal infrastructure details from SSR state, serializing only non-sensitive data the client needs.`

	ModuleConfirmation = "Candidate for substantive private credentials in parsed state; routine identity data and public identifiers remain observations until sensitivity and authorization are established"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
