package fastify_hono_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "fastify-hono-probe"
	ModuleName  = "Fastify/Hono Probe"
	ModuleShort = "Detects exposed Fastify and Hono framework endpoints"
)

var (
	ModuleDesc = `**What it means:** A Fastify or Hono Node.js app exposes internal framework endpoints in production - Swagger/OpenAPI docs, a Scalar API reference, or a metrics endpoint at paths like /documentation/json, /reference, or /.well-known/fastify/metrics - leaking the API surface and runtime state to anonymous users.

**How it's exploited:** An attacker reads the OpenAPI/Swagger spec to map every route, parameter, and auth requirement, turning a black-box target into a documented attack surface for parameter fuzzing and admin-endpoint abuse.

**Fix:** Disable or restrict the Swagger, documentation, metrics, and overview routes in production, gating them behind authentication or an internal-only network.`

	ModuleConfirmation = "Confirmed when the server responds with framework-specific content at known documentation or debug paths, indicating exposed internal endpoints"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nodejs", "misconfiguration", "light"}
)
