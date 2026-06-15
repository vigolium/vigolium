package rails_active_storage_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-probe"
	ModuleName  = "Rails Active Storage Probe"
	ModuleShort = "Detects exposed Rails Active Storage direct upload and Action Mailbox ingress endpoints"
)

var (
	ModuleDesc = `**What it means:** Rails Active Storage direct-upload, blob, or Action Mailbox inbound-email ingress routes are reachable at the network edge - internal upload and mail-ingest routes that widen the attack surface.

**How it's exploited:** An unauthenticated direct-upload endpoint lets an attacker push arbitrary blobs to storage; an open Action Mailbox ingress accepts forged inbound emails the app processes as legitimate. The probe confirms only that the route is mounted and answers.

**Fix:** Require authentication on Active Storage and Action Mailbox routes, configure ingress credentials, and keep these routes off untrusted networks.`

	ModuleConfirmation = "Tentatively flagged when an Active Storage / Action Mailbox OPTIONS probe returns a 2xx POST-only Allow header (subset of POST/OPTIONS) that a random sibling path does not reproduce, or a blob route redirects to a stored object"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "file-exposure", "light"}
)
