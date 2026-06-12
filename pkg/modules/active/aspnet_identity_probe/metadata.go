package aspnet_identity_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-identity-probe"
	ModuleName  = "ASP.NET Identity Probe"
	ModuleShort = "Detects exposed ASP.NET Identity endpoints, IdentityServer discovery, and authentication misconfigurations"
)

var (
	ModuleDesc = `**What it means:** The host publicly exposes ASP.NET Identity authentication surfaces that should be locked down or are otherwise sensitive: scaffolded Identity UI pages (login, register, password reset), IdentityServer/Duende OAuth2/OIDC endpoints (token, authorize, JWKS), the ASP.NET Core 8+ Identity API endpoints (register, manage/info), and the OIDC discovery document. The most serious case is the management API (/manage/info) returning account data without authentication; an open registration endpoint and the broader exposed auth attack surface are also reported. The disclosure ranges from informational fingerprinting to a real authentication gap.

**How it's exploited:** An attacker uses an unauthenticated /manage/info or open register endpoint to read or create accounts directly, brute-forces or credential-stuffs an unthrottled token endpoint, enumerates valid emails via the password-reset page, and maps token endpoints, scopes, grant types, and signing keys from the discovery and JWKS documents to plan further attacks.

**Fix:** Restrict registration and Identity management endpoints behind authorization, enforce rate limiting on token and reset endpoints, and remove or protect any scaffolded Identity pages not needed in production.`

	ModuleConfirmation = "Confirmed when Identity endpoints or OIDC discovery documents are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "auth-bypass", "probe", "moderate"}
)
