package api_pagination_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-pagination-leak"
	ModuleName  = "API Pagination Leak"
	ModuleShort = "Detects API pagination metadata that reveals total record counts"
)

var (
	ModuleDesc = `## Description
Passively detects API pagination metadata in JSON responses that reveals total record
counts, page counts, or cursor-based navigation details. This information can disclose
how many records exist in a collection, which may reveal business-sensitive data such as
user counts, order volumes, or internal resource quantities.

## Notes
- Checks JSON response bodies for common pagination fields (total_count, total, totalItems, etc.)
- Only triggers on JSON responses to avoid false positives
- Deduplicates by host+path to avoid redundant findings
- Reports matched fields and their values as extracted results

## References
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when JSON response contains pagination metadata fields exposing total record counts or page navigation details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
