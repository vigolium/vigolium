package server_action_input_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-input-audit"
	ModuleName  = "Server Action Input Audit"
	ModuleShort = "Detects Next.js Server Actions missing runtime input validation"
)

var (
	ModuleDesc = `**What it means:** A Next.js Server Action (a server-side handler marked with the "use server" directive) was found in served JavaScript or TypeScript that reads user-supplied input (FormData fields or function arguments) and uses it in database operations without any runtime schema validation. TypeScript types are erased at runtime, so without a validation library (zod, yup, joi, valibot, superstruct, etc.) the action trusts whatever data the client sends. This is a passive, source-code-pattern finding (Tentative confidence): it flags a likely missing-validation pattern, not a confirmed exploitable bug.

**How it's exploited:** An attacker invokes the Server Action directly with crafted FormData or arguments, supplying unexpected types, extra fields, or injection payloads (for example NoSQL/ORM operators, mass-assignment fields, or oversized values) that reach the database write or query unchecked, potentially corrupting data, bypassing business logic, or enabling injection.

**Fix:** Validate and coerce every Server Action input at runtime with a schema validation library (zod safeParse, yup, joi, valibot) before using it in any database or sensitive operation.`

	ModuleConfirmation = "Confirmed when a Server Action processes input without any runtime validation library"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
