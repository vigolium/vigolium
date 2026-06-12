package idor_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-detection"
	ModuleName  = "IDOR Detection"
	ModuleShort = "Detects missing authorization on object ID parameters (IDOR/BOLA)"
)

var (
	ModuleDesc = `**What it means:** The application exposes a direct object reference (an ID in a URL parameter, body field, or path segment) that is not protected by a per-user authorization check. This is an Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA) flaw, meaning one user can read or act on records that belong to other users.

**How it's exploited:** An attacker takes a request for their own object and increments or substitutes the ID to a neighbor value (user_id=42 to 41/43, or an adjacent code or base64 ID). Here the server returned a structurally similar but different response for the neighbor ID instead of a 401/403/404 or login redirect, so the attacker can enumerate IDs to harvest other users' data or tamper with records they should not access.

**Fix:** Enforce object-level authorization on every request by verifying that the authenticated session owns or is permitted to access the referenced object, and prefer unpredictable identifiers so IDs cannot be guessed or enumerated.`

	ModuleConfirmation = "Indicated when a probe request with a neighbor object ID returns a structurally similar response with different content, suggesting missing authorization enforcement"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
