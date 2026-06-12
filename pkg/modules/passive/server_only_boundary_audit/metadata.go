package server_only_boundary_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-only-boundary-audit"
	ModuleName  = "Server-Only Boundary Audit"
	ModuleShort = "Detects server-side modules leaked into client component bundles"
)

var (
	ModuleDesc = `**What it means:** A Next.js client-side JavaScript bundle (served under /_next/static/) contains code meant to run only on the server, such as a database client (Prisma, Drizzle, Knex/Sequelize), a server crypto or JWT library (bcrypt, jose, jsonwebtoken), Node core modules (fs, path, child_process), an internal service URL, or a database connection string with embedded credentials. This indicates the server/client boundary was not enforced and internal implementation detail has shipped to every visitor's browser.
**How it's exploited:** Anyone loading the page can read the bundle, mapping internal endpoints, database schemas, ORM queries, and auth logic to plan targeted attacks; a leaked connection string or signing key can be used directly to reach the database or forge tokens. Findings are Tentative because minified vendor bundles carry these identifiers incidentally, so two distinct signals (or a credentialed connection string) are required.
**Fix:** Wrap server-only modules with the server-only package and keep secrets, database clients, and internal URLs out of any code imported by client components.`

	ModuleConfirmation = "Confirmed when client-side JavaScript bundles contain server-only module identifiers or internal service references"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "info-disclosure", "light"}
)
