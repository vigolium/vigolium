package server_action_input_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-input-audit"
	ModuleName  = "Server Action Input Audit"
	ModuleShort = "Detects Next.js Server Actions missing runtime input validation"
)

var (
	ModuleDesc = `**What it means:** A source-like JS/TS file contains server-action, input-access, and database-operation patterns without a recognized schema-library token. This is file-level proximity, not proven source-to-sink flow.

**How it's exploited:** Exploitation requires attacker input to reach a sensitive operation without imported or manual validation. The module neither resolves helpers nor executes payloads, so it reports a candidate.

**Fix:** Validate and coerce every Server Action input at runtime with a schema library before any database operation.`

	ModuleConfirmation = "Candidate when source-like code co-locates action, input, and write patterns without recognized validation; connected flow or dynamic impact is required"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
