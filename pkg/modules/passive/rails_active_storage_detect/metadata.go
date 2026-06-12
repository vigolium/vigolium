package rails_active_storage_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-detect"
	ModuleName  = "Rails Active Storage Detect"
	ModuleShort = "Passively detects Active Storage URLs and direct upload references in responses"
)

var (
	ModuleDesc = `**What it means:** The application uses Rails Active Storage for file attachments, detected passively in an HTML response via Active Storage blob, representation, or disk URLs (/rails/active_storage/...), direct-upload form attributes, or Active Storage JavaScript references. This is an informational fingerprint, not a confirmed vulnerability: the risk is that Active Storage blob URLs are served directly and may be reachable by anyone who knows or guesses the URL, without the application enforcing its own authorization on the download.

**How it's exploited:** Knowing Active Storage is in use lets an attacker map the file-handling attack surface and probe exposed blob, representation, and direct-upload endpoints. If a leaked or enumerated blob URL points to a private upload that lacks application-level access control, the attacker can retrieve another user's file directly, leaking sensitive documents or images.

**Fix:** Serve private attachments through controller actions that enforce authorization, prefer authenticated or expiring URLs over public blob links, and avoid embedding sensitive direct-upload or blob URLs in pages reachable by unauthorized users.`

	ModuleConfirmation = "Confirmed when Active Storage URL patterns or direct upload attributes are found in responses"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "file-exposure", "light"}
)
