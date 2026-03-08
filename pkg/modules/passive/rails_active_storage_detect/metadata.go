package rails_active_storage_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-rails-active-storage-detect"
	ModuleName  = "Rails Active Storage Detect"
	ModuleShort = "Passively detects Active Storage URLs and direct upload references in responses"
)

var (
	ModuleDesc = `## Description
Passively detects Rails Active Storage usage by scanning response bodies for Active
Storage blob URLs, representation URLs, and direct upload form attributes. Flags
potentially publicly accessible file attachments.

## Notes
- Passive only: does not send any HTTP requests
- Scans HTML bodies for /rails/active_storage/ URL patterns
- Detects data-direct-upload-url attributes in forms
- Identifies activestorage JavaScript references
- Deduplicates by host

## References
- https://guides.rubyonrails.org/active_storage_overview.html`

	ModuleConfirmation = "Confirmed when Active Storage URL patterns or direct upload attributes are found in responses"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"rails", "ruby", "fingerprint", "file-exposure", "light"}
)
