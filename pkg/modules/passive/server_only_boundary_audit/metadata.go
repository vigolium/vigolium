package server_only_boundary_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-only-boundary-audit"
	ModuleName  = "Server-Only Boundary Audit"
	ModuleShort = "Detects server-side modules leaked into client component bundles"
)

var (
	ModuleDesc = `**What it means:** A Next.js client bundle under /_next/static/ contains server-only code such as a database client (Prisma), a crypto/JWT library (jose), Node modules (fs, child_process), an internal service URL, or a credentialed connection string. The server/client boundary was not enforced and internal detail shipped to the browser.

**How it's exploited:** Anyone loading the page reads the bundle, mapping internal endpoints and auth logic; a leaked connection string or key reaches the database or forges tokens. Tentative, so two signals are required.

**Fix:** Wrap server-only modules with the server-only package and keep secrets and internal URLs out of client code.`

	ModuleConfirmation = "Confirmed when client-side JavaScript bundles contain server-only module identifiers or internal service references"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "info-disclosure", "light"}
)
