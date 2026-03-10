package aspnet_identity_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-identity-probe"
	ModuleName  = "ASP.NET Identity Probe"
	ModuleShort = "Detects exposed ASP.NET Identity endpoints, IdentityServer discovery, and authentication misconfigurations"
)

var (
	ModuleDesc = `## Description
Probes for exposed ASP.NET Identity scaffolded pages, IdentityServer/Duende OIDC
discovery documents, and authentication-related misconfigurations. Exposed OIDC
discovery documents reveal token endpoints, supported scopes, and grant types.
Open registration endpoints may allow unauthorized account creation. Scaffolded
Identity UI pages confirm the authentication framework in use.

## Notes
- Runs once per host
- Probes Identity UI, OIDC discovery, and token endpoints
- Extracts OIDC metadata (scopes, grant types, endpoints) as evidence
- Fingerprints 404 to avoid false positives

## References
- https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity
- https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization
- https://openid.net/specs/openid-connect-discovery-1_0.html`

	ModuleConfirmation = "Confirmed when Identity endpoints or OIDC discovery documents are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "auth-bypass", "probe", "moderate"}
)
