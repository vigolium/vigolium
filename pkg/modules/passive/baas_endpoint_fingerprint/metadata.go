package baas_endpoint_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "baas-endpoint-fingerprint"
	ModuleName  = "BaaS Endpoint Fingerprint"
	ModuleShort = "Identifies third-party backend / identity / serverless providers referenced in responses"
)

var (
	ModuleDesc = `**What it means:** Responses are matched against a catalog of backend-as-a-service, identity, and serverless providers - Okta, Auth0, Cognito, Supabase, Convex, Lambda URLs, Hasura, Sentry. Each hit records the provider, category, and tenant/instance identifier. Informational recon, no new traffic.

**How it's exploited:** Each referenced backend is a distinct, externally hosted attack surface. The tenant identifier (an Okta org, a Supabase project ref) tells an attacker which managed instance to probe for weak auth rules or public data.

**Fix:** Treat these identifiers as public, but enforce the provider's access controls (tenant rules, row-level security) so the endpoint grants no data access.`

	ModuleConfirmation = "Confirmed when a known backend/identity/serverless provider endpoint is referenced in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"recon", "baas", "fingerprint", "light"}
)
