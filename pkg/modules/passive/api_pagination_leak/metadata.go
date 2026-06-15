package api_pagination_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-pagination-leak"
	ModuleName  = "API Pagination Leak"
	ModuleShort = "Detects API pagination metadata that reveals total record counts"
)

var (
	ModuleDesc = `**What it means:** A JSON API response exposes pagination metadata (total_count, totalItems, total_pages, or record counts) revealing a collection's full size. This can disclose business-sensitive figures - total user, order, or transaction volumes - even when only one page is returned.

**How it's exploited:** An attacker reads the total to infer collection size, then walks pagination parameters (page, per_page, limit, offset, cursor) to enumerate the dataset, including unauthorized records where object-level authorization is missing.

**Fix:** Remove total-count and page-count metadata unless required, prefer cursor-based navigation, and enforce per-object authorization so pagination cannot enumerate restricted records.`

	ModuleConfirmation = "Confirmed when JSON response contains pagination metadata fields exposing total record counts or page navigation details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
