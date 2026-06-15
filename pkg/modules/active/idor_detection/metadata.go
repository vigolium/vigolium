package idor_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-detection"
	ModuleName  = "IDOR Detection"
	ModuleShort = "Detects missing authorization on object ID parameters (IDOR/BOLA)"
)

var (
	ModuleDesc = `**What it means:** The application exposes a direct object reference (an ID in a parameter, body field, or path) lacking a per-user authorization check - an IDOR / Broken Object Level Authorization (BOLA) flaw letting one user read others' records.

**How it's exploited:** An attacker substitutes the ID with a neighbor value (user_id=42 to 41/43). Here the server returned a structurally similar but different response instead of 401/403/404, so IDs can be enumerated to harvest other users' data.

**Fix:** Enforce object-level authorization on every request by verifying the session may access the referenced object, and prefer unpredictable identifiers.`

	ModuleConfirmation = "Indicated when a probe request with a neighbor object ID returns a structurally similar response with different content, suggesting missing authorization enforcement"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
