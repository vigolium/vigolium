package ssr_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-data-exposure"
	ModuleName  = "SSR Data Exposure"
	ModuleShort = "Detects sensitive data leaked in server-side rendered state blobs"
)

var (
	ModuleDesc = `**What it means:** Modern JS frameworks serialize application state into the HTML page so the client can hydrate it, embedding it in blobs such as __NEXT_DATA__, __NUXT__, __INITIAL_STATE__, and __APOLLO_STATE__. This module found one or more sensitive values inside that server-rendered state, meaning data that should stay server-side is being shipped to every visitor in the page source.

**How it's exploited:** Anyone who views the page source (no authentication or special tooling required) can read the leaked values. Depending on what was matched, this can hand an attacker live API keys or access tokens, AWS access keys, database connection strings, internal/private IP addresses that map the backend, user email addresses, password hashes, or an admin/privilege flag that reveals high-value accounts. These secrets can then be replayed directly against the relevant service or used to expand an attack.

**Fix:** Strip secrets, credentials, internal infrastructure details, and other sensitive fields from the data serialized into SSR state, sending only the minimum non-sensitive data the client actually needs to render.`

	ModuleConfirmation = "Confirmed when sensitive patterns (API keys, tokens, admin flags, credentials) are found in SSR state blobs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
