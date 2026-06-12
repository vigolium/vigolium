package fastify_hono_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastify-hono-probe"
	ModuleName  = "Fastify/Hono Probe"
	ModuleShort = "Detects exposed Fastify and Hono framework endpoints"
)

var (
	ModuleDesc = `**What it means:** A Fastify or Hono Node.js application is exposing internal framework endpoints in production. The scanner confirmed reachable Swagger/OpenAPI documentation, Swagger UI, a Scalar API reference, a runtime metrics endpoint, or the Fastify overview plugin at well-known framework paths such as /documentation/json, /doc, /ui, /reference, or /.well-known/fastify/metrics. These resources are meant for development and leak the application's API surface and internal runtime state to anonymous users.

**How it's exploited:** An attacker reads the exposed OpenAPI/Swagger spec to map every route, parameter, and authentication requirement, turning a black-box target into a documented attack surface that speeds up parameter fuzzing, authorization testing, and abuse of undocumented or admin endpoints. Exposed metrics (Prometheus or Node heap/event-loop data) further reveal internal behavior and can aid timing or resource-exhaustion analysis.

**Fix:** Disable or restrict the Swagger, documentation, metrics, and overview routes in production, gating them behind authentication or an internal-only network so they are not reachable by anonymous users.`

	ModuleConfirmation = "Confirmed when the server responds with framework-specific content at known documentation or debug paths, indicating exposed internal endpoints"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nodejs", "misconfiguration", "light"}
)
