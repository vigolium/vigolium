package authz_compare

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "authz-compare"
	ModuleName  = "Cross-Session Authorization Compare"
	ModuleShort = "Compares responses across authenticated sessions to detect IDOR/BOLA"
)

var (
	ModuleDesc = `## Description
Detects Broken Object Level Authorization (BOLA) and Insecure Direct Object Reference
(IDOR) by replaying the same request with different authenticated sessions and comparing
responses.

When multiple sessions are configured (via --session or --auth-config), this module
replays each request observed by the primary session using the compare sessions. It then
analyzes the response differences to detect missing authorization enforcement.

## Detection Logic
For each request from the primary session:
1. Skip static assets, media files, and non-authenticated endpoints
2. Replay the request with each compare session's credentials
3. Compare primary vs compare responses:
   - Primary 200, Compare 401/403 → properly enforced (skip)
   - Primary 200, Compare 302→login → properly enforced (skip)
   - Primary 200, Compare 200 (same content) → public data (skip)
   - Primary 200, Compare 200 (different content) → IDOR/BOLA finding
   - Primary non-200 → skip (primary can't access either)

## Requirements
- At least 2 sessions must be configured: one primary and one or more compare sessions
- Sessions are configured via ` + "`--session`" + `, ` + "`--auth-config`" + `, or ` + "`--session-file`" + ` CLI flags

## Notes
- This module is automatically skipped when no compare sessions are configured
- Covers OWASP API1:2023 (Broken Object Level Authorization)
- Complements the idor-detection module which tests neighbor IDs within a single session
- Uses structural response comparison from authzutil for robust matching

## References
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html`

	ModuleConfirmation = "Indicated when two different authenticated sessions receive structurally similar 200 responses with different content at the same endpoint, suggesting missing authorization enforcement"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "bola", "auth-bypass", "access-control", "api-security", "moderate"}
)
