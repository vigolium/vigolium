package graphql_introspection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-introspection-detect"
	ModuleName  = "GraphQL Introspection Leak Detect"
	ModuleShort = "Detects GraphQL introspection responses that expose the full API schema"
)

var (
	ModuleDesc = `**What it means:** A captured JSON response structurally contains GraphQL data.__schema or data.__type with usable type information. This observes schema discovery, which many public GraphQL APIs intentionally support.

**How it's exploited:** Schema knowledge helps reconnaissance, but it does not show that a resolver is unauthorized, data is sensitive, or mutations are callable. Those require separate active authorization tests.

**Fix:** Disable GraphQL introspection in production (set introspection to false) and restrict schema access to trusted internal or development environments only.`

	ModuleConfirmation = "Observed only when parsed JSON contains a usable data.__schema or data.__type object; resolver access and sensitivity are not inferred"
	// Introspection being enabled is schema disclosure / a hardening gap, not a
	// vulnerability on its own — many public GraphQL APIs enable it by design — so
	// it is a Low-severity lead rather than Medium.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"graphql", "api", "info-disclosure", "light"}
)
