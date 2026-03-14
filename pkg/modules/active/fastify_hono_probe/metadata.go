package fastify_hono_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastify-hono-probe"
	ModuleName  = "Fastify/Hono Probe"
	ModuleShort = "Detects exposed Fastify and Hono framework endpoints"
)

var (
	ModuleDesc = `## Description
Probes for framework-specific documentation, metrics, and debug endpoints exposed
by Fastify and Hono Node.js frameworks. These frameworks may inadvertently expose
Swagger documentation, API references, metrics endpoints, and overview pages in
production deployments.

## Notes
- Runs once per host with internal deduplication
- Tests 8 framework-specific paths across Fastify and Hono
- Each probe has tailored response matching to reduce false positives

## References
- https://fastify.dev/docs/latest/
- https://hono.dev/docs/`

	ModuleConfirmation = "Confirmed when the server responds with framework-specific content at known documentation or debug paths, indicating exposed internal endpoints"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nodejs", "misconfiguration", "light"}
)
