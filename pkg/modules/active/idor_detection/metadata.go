package idor_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-detection"
	ModuleName  = "IDOR Detection"
	ModuleShort = "Detects missing authorization on object ID parameters (IDOR/BOLA)"
)

var (
	ModuleDesc = `## Description
Actively tests for Insecure Direct Object Reference (IDOR) and Broken Object Level
Authorization (BOLA) vulnerabilities by substituting ID parameters with neighbor values
and comparing responses.

The module targets parameters classified as object identifiers by the passive IDOR module
(sequential integers, structured codes, base64-encoded IDs, UUIDv1, emails). For each
candidate, it generates predictable neighbor IDs and sends probe requests to detect
whether the server enforces authorization.

## Detection Logic
1. Classify parameter via authzutil.ClassifyParam — skip if not an object ID or low predictability
2. Generate neighbor IDs (e.g., user_id=42 → 41, 43) via authzutil.GenerateNeighborIDs
3. Fetch baseline response for the original request
4. Send probe requests with neighbor IDs and compare responses:
   - 401/403/404 or login redirect → authorization enforced (skip)
   - Soft-denial body strings → authorization enforced (skip)
   - Content identical → public data, not IDOR (skip)
   - Structurally different → different resource type (skip)
   - Structurally similar + different content → potential IDOR finding

## Notes
- Covers OWASP API1:2023 (Broken Object Level Authorization)
- Limited to 50 probes per host to avoid excessive traffic
- Only tests parameters with predictable ID formats (skips UUIDv4, random hex)
- Confidence promoted to Firm when user-specific fields differ between responses

## References
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html
- https://portswigger.net/web-security/access-control/idor`

	ModuleConfirmation = "Indicated when a probe request with a neighbor object ID returns a structurally similar response with different content, suggesting missing authorization enforcement"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
