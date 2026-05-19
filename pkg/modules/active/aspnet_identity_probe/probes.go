package aspnet_identity_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// OIDC Discovery (IdentityServer4 / Duende / ASP.NET Core Identity API)
	{
		path:        "/.well-known/openid-configuration",
		name:        "OIDC Discovery Document",
		markers:     []string{"issuer", "authorization_endpoint", "token_endpoint", "scopes_supported"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "OpenID Connect discovery document exposed, revealing authorization endpoints, supported scopes, grant types, and token signing configuration",
	},
	// IdentityServer / Duende endpoints
	{
		path:        "/connect/token",
		name:        "Token Endpoint",
		markers:     []string{"error", "invalid_client", "invalid_grant", "unsupported_grant_type"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "OAuth2/OIDC token endpoint accessible, may be susceptible to brute force or credential stuffing without rate limiting",
	},
	{
		path:        "/connect/authorize",
		name:        "Authorization Endpoint",
		markers:     []string{"client_id", "redirect_uri", "response_type", "error"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "OAuth2/OIDC authorization endpoint detected, confirming IdentityServer/Duende deployment",
	},
	{
		path:        "/.well-known/openid-configuration/jwks",
		name:        "JWKS Endpoint",
		markers:     []string{"keys", "kty", "use", "kid"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "JSON Web Key Set endpoint exposed, revealing public signing keys used for token validation",
	},
	// Scaffolded ASP.NET Identity UI
	{
		path:        "/Identity/Account/Register",
		name:        "Identity Register (Scaffolded)",
		markers:     []string{"Register", "Email", "Password", "ConfirmPassword", "__RequestVerificationToken"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET Identity registration page publicly accessible, potentially allowing unauthorized account creation",
	},
	{
		path:        "/Identity/Account/Login",
		name:        "Identity Login (Scaffolded)",
		markers:     []string{"Log in", "Email", "Password", "RememberMe", "__RequestVerificationToken"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity scaffolded login page detected, confirming Identity UI deployment",
	},
	{
		path:        "/Identity/Account/ForgotPassword",
		name:        "Identity Password Reset",
		markers:     []string{"Forgot", "Email", "password", "__RequestVerificationToken"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity password reset page exposed, may enable email enumeration",
	},
	// MVC-style Identity endpoints
	{
		path:        "/Account/Register",
		name:        "MVC Register",
		markers:     []string{"Register", "Email", "Password", "__RequestVerificationToken"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET MVC registration endpoint publicly accessible",
	},
	// API-based Identity (ASP.NET Core 8+ Identity API endpoints)
	{
		path:        "/register",
		name:        "Identity API Register",
		markers:     []string{"email", "password", "errors", "title", "type"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "ASP.NET Core Identity API registration endpoint accessible, may allow unauthorized account creation via API",
	},
	{
		path:        "/manage/info",
		name:        "Identity API Manage Info",
		markers:     []string{"email", "isEmailConfirmed"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE", "401"},
		sev:         severity.High,
		desc:        "ASP.NET Core Identity management API accessible without proper authentication",
	},
}
