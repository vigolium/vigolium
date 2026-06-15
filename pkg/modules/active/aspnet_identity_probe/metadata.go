package aspnet_identity_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-identity-probe"
	ModuleName  = "ASP.NET Identity Probe"
	ModuleShort = "Detects exposed ASP.NET Identity endpoints, IdentityServer discovery, and authentication misconfigurations"
)

var (
	ModuleDesc = `**What it means:** The host publicly exposes sensitive ASP.NET Identity surfaces: scaffolded UI pages (login, register, reset), IdentityServer/Duende OIDC endpoints (token, JWKS), the ASP.NET Core 8+ Identity API (register, manage/info), and the OIDC discovery document. The worst case is /manage/info returning account data.

**How it's exploited:** An attacker uses unauthenticated /manage/info or open register to read or create accounts, credential-stuffs an unthrottled token endpoint, enumerates emails via the reset page, and maps scopes and signing keys from the JWKS document.

**Fix:** Restrict registration and management endpoints behind authorization, rate-limit token and reset endpoints, and remove unneeded scaffolded pages.`

	ModuleConfirmation = "Confirmed when Identity endpoints or OIDC discovery documents are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "auth-bypass", "probe", "moderate"}
)
