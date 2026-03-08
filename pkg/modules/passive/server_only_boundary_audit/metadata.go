package server_only_boundary_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-only-boundary-audit"
	ModuleName  = "Server-Only Boundary Audit"
	ModuleShort = "Detects server-side modules leaked into client component bundles"
)

var (
	ModuleDesc = `## Description
Scans client-side JavaScript bundles for evidence that server-only code has leaked
into the browser. Server-side modules (database clients, internal API helpers, crypto
operations, environment secrets) should use the 'server-only' package to enforce the
boundary. When this guard is missing, Next.js may accidentally bundle server code into
the client, exposing proprietary logic, internal endpoints, and potentially credentials.

## Notes
- Passive only - does not send any HTTP requests
- Scans JS response bodies under /_next/static/ paths
- Detects server-side module identifiers in client bundles (prisma, drizzle, knex, etc.)
- Detects internal API endpoint patterns (localhost, 127.0.0.1, internal service URLs)
- Detects server crypto/auth module usage (bcrypt, jsonwebtoken, jose)
- Deduplicates by host+path

## References
- https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns#keeping-server-only-code-out-of-the-client-environment
- https://cwe.mitre.org/data/definitions/200.html
- https://cwe.mitre.org/data/definitions/540.html`

	ModuleConfirmation = "Confirmed when client-side JavaScript bundles contain server-only module identifiers or internal service references"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"nextjs", "javascript", "info-disclosure", "light"}
)
