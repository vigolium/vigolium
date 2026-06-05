package idor_guid

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-guid"
	ModuleName  = "IDOR GUID Predictability"
	ModuleShort = "Detects predictable GUID patterns like UUIDv1 with extractable timestamps"
)

var (
	ModuleDesc = `## Description
Detects Insecure Direct Object Reference (IDOR) vulnerabilities arising from predictable GUID/UUID patterns.
UUIDv1 encodes a timestamp and MAC address, making sequential IDs guessable. This module identifies
parameters containing UUIDv1 values, extracts their timestamps, generates time-neighbor UUIDs, and
checks if the application returns valid responses for those predicted identifiers.`
	ModuleConfirmation = "Confirmed when a predicted neighbor identifier returns a 200 response that is a distinct application object — not a login/SSO challenge or access-denied page, and differing from the baseline by more than the endpoint's own per-request variation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
