package api_pagination_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-pagination-leak"
	ModuleName  = "API Pagination Leak"
	ModuleShort = "Detects API pagination metadata that reveals total record counts"
)

var (
	ModuleDesc = `**What it means:** A structurally valid JSON response contains a large numeric total plus at least two pagination-context fields. Total counts are standard behavior for many public and private APIs.

**How it's exploited:** A count may reveal a business metric, but this module does not know whether the collection is sensitive and does not prove that walking pages returns unauthorized records. It remains an observation.

**Fix:** Remove total-count and page-count metadata unless required, prefer cursor-based navigation, and enforce per-object authorization so pagination cannot enumerate restricted records.`

	ModuleConfirmation = "Observed after JSON parsing, a total of at least 1000, and two pagination-context markers; collection sensitivity and record authorization are not inferred"
	// Exposing a pagination total is an information-exposure lead, not a
	// vulnerability on its own — nearly every paginated REST API (Zendesk, GitHub,
	// JSON:API, …) returns these standard envelope fields. It only matters when the
	// count reveals a genuinely large, business-sensitive collection, so this is a
	// Low-severity lead for manual assessment rather than a Medium finding.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"api", "info-disclosure", "light"}
)
