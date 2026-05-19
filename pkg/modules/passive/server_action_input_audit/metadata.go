package server_action_input_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-input-audit"
	ModuleName  = "Server Action Input Audit"
	ModuleShort = "Detects Next.js Server Actions missing runtime input validation"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js Server Actions that accept
user input (FormData or function arguments) without runtime schema validation. Server
Actions rely on TypeScript types for compile-time safety, but these types are erased at
runtime. Without runtime validation (zod, yup, joi, valibot, etc.), attackers can submit
arbitrary data types, unexpected fields, or injection payloads.

## Notes
- Passive only - does not send any HTTP requests
- Detects "use server" directive combined with FormData/argument usage
- Flags when no validation library patterns are found (z.parse, z.safeParse, schema.validate, etc.)
- Complements server_action_auth which checks for missing authorization
- Deduplicates by host+path
- CWE-20: Improper Input Validation

## References
- https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations
- https://nextjs.org/blog/security-nextjs-server-components-actions
- https://cwe.mitre.org/data/definitions/20.html`

	ModuleConfirmation = "Confirmed when a Server Action processes input without any runtime validation library"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
