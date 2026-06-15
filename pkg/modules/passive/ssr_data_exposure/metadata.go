package ssr_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-data-exposure"
	ModuleName  = "SSR Data Exposure"
	ModuleShort = "Detects sensitive data leaked in server-side rendered state blobs"
)

var (
	ModuleDesc = `**What it means:** JS frameworks serialize application state into the HTML for client hydration, in blobs such as __NEXT_DATA__, __NUXT__, and __APOLLO_STATE__. This module found sensitive values inside that server-rendered state, so data meant to stay server-side ships to every visitor in the page source.

**How it's exploited:** Anyone viewing the page source (no authentication) reads the leaked values - API keys, AWS keys, connection strings, internal IPs, emails, password hashes, or admin flags - then replays them against the relevant service.

**Fix:** Strip secrets, credentials, and internal infrastructure details from SSR state, serializing only non-sensitive data the client needs.`

	ModuleConfirmation = "Confirmed when sensitive patterns (API keys, tokens, admin flags, credentials) are found in SSR state blobs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
