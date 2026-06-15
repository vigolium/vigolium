package bfla_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "bfla-detection"
	ModuleName  = "BFLA Detection"
	ModuleShort = "Detects Broken Function-Level Authorization on privileged endpoints"
)

var (
	ModuleDesc = `**What it means:** A privileged endpoint (for example /admin or /users/delete) returns the same successful content even when credentials are removed, an invalid token is supplied, or the method is changed. This is Broken Function-Level Authorization: no access control on a function meant for authorized roles.

**How it's exploited:** Any anonymous user calls the endpoint to read privileged data or trigger admin actions, since credentials are not required and write methods succeed unauthenticated, enabling data disclosure or administrative takeover.

**Fix:** Enforce server-side authorization on every privileged endpoint and method, validating identity and role on each request and denying by default.`

	ModuleConfirmation = "Confirmed when a privileged endpoint returns a successful response after removing or downgrading authentication credentials"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"auth-bypass", "api-security", "moderate"}
)
