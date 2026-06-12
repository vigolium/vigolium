package bfla_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "bfla-detection"
	ModuleName  = "BFLA Detection"
	ModuleShort = "Detects Broken Function-Level Authorization on privileged endpoints"
)

var (
	ModuleDesc = `**What it means:** An administrative or privileged endpoint (for example /admin, /actuator, /users/delete, /config) returns the same successful, privileged content even when the request's credentials are removed, replaced with an invalid token, or the HTTP method is changed. This is Broken Function-Level Authorization: the server enforces no access control on a function that should be restricted to authorized roles.

**How it's exploited:** Any anonymous user can call the endpoint directly to read privileged data or trigger administrative actions, since the module confirmed the original request's Authorization and Cookie headers are not required, an invalid Bearer token is accepted, or write methods (POST, PUT, DELETE) succeed without authentication. Depending on the function this can lead to data disclosure, account or resource manipulation, or full administrative takeover.

**Fix:** Enforce server-side authorization on every privileged endpoint and HTTP method, validating the caller's identity and role on each request and denying access by default rather than relying on the UI or path obscurity.`

	ModuleConfirmation = "Confirmed when a privileged endpoint returns a successful response after removing or downgrading authentication credentials"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"auth-bypass", "api-security", "moderate"}
)
