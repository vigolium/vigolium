package rails_active_storage_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-detect"
	ModuleName  = "Rails Active Storage Detect"
	ModuleShort = "Passively detects Active Storage URLs and direct upload references in responses"
)

var (
	ModuleDesc = `**What it means:** The application uses Rails Active Storage for file attachments, detected passively via blob URLs (/rails/active_storage/...), direct-upload attributes, or JS references. An informational fingerprint: blob URLs are served directly and may be reachable by anyone who guesses them.

**How it's exploited:** An attacker probes exposed blob and direct-upload endpoints. If a leaked or enumerated blob URL points to a private upload lacking access control, they retrieve another user's file directly, leaking sensitive documents.

**Fix:** Serve private attachments through controller actions that enforce authorization, prefer authenticated or expiring URLs, and avoid embedding sensitive blob URLs in public pages.`

	ModuleConfirmation = "Confirmed when Active Storage URL patterns or direct upload attributes are found in responses"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "file-exposure", "light"}
)
