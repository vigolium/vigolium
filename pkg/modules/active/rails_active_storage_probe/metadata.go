package rails_active_storage_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-probe"
	ModuleName  = "Rails Active Storage Probe"
	ModuleShort = "Detects exposed Rails Active Storage direct upload and Action Mailbox ingress endpoints"
)

var (
	ModuleDesc = `**What it means:** The application exposes Rails Active Storage direct-upload, Active Storage blob, or Action Mailbox inbound-email ingress routes that are reachable without authentication at the network edge. These framework routes are meant for internal upload and mail-ingest flows, and exposing them widens the attack surface and signals the app may not gate them properly.

**How it's exploited:** If a direct-upload endpoint accepts unauthenticated requests, an attacker can upload arbitrary file blobs to the app's storage, potentially seeding malicious content or burning storage and bandwidth. An open Action Mailbox ingress lets an attacker inject forged inbound emails that the app processes as legitimate. An exposed blob route confirms Active Storage is in use and may serve stored files publicly. This probe confirms only that the route is mounted and answers; it does not by itself prove the upload or ingest succeeds without further auth.

**Fix:** Require authentication on Active Storage and Action Mailbox routes (configure ingress credentials and restrict access), and do not expose these internal routes to untrusted networks.`

	ModuleConfirmation = "Confirmed when an Active Storage / Action Mailbox OPTIONS probe returns a 2xx Allow header advertising POST, or a blob route redirects to a stored object"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "file-exposure", "light"}
)
