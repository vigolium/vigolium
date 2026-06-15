package server_action_input_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-input-audit"
	ModuleName  = "Server Action Input Audit"
	ModuleShort = "Detects Next.js Server Actions missing runtime input validation"
)

var (
	ModuleDesc = `**What it means:** A Next.js "use server" Server Action reads user input (FormData or arguments) and uses it in database operations with no runtime schema validation. TypeScript types are erased at runtime, so without a library like zod the action trusts whatever the client sends. Tentative source-pattern finding.

**How it's exploited:** An attacker invokes the action directly with unexpected types, extra fields, or injection payloads (NoSQL operators, mass-assignment) that reach the query unchecked, corrupting data or bypassing business logic.

**Fix:** Validate and coerce every Server Action input at runtime with a schema library before any database operation.`

	ModuleConfirmation = "Confirmed when a Server Action processes input without any runtime validation library"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
