package api_pagination_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-pagination-leak"
	ModuleName  = "API Pagination Leak"
	ModuleShort = "Detects API pagination metadata that reveals total record counts"
)

var (
	ModuleDesc = `**What it means:** A JSON API response exposes pagination metadata (fields such as total_count, totalItems, total_pages, or record counts) that reveals the full number of records in a collection. This count can disclose business-sensitive figures the application did not intend to publish, such as total user, order, or transaction volumes, even when the response only returns one page of items.

**How it's exploited:** An attacker reads the total-count value to infer collection size and map attack surface, then walks the pagination parameters (page, per_page, limit, offset, cursor) to enumerate the entire dataset, including records they are not authorized to see if the endpoint also lacks object-level authorization. The disclosed totals can also leak competitive or internal-scale intelligence.

**Fix:** Remove total-count and full-page-count metadata from API responses unless required, return only cursor-based or relative navigation, and enforce per-object authorization so pagination cannot be used to enumerate restricted records.`

	ModuleConfirmation = "Confirmed when JSON response contains pagination metadata fields exposing total record counts or page navigation details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
