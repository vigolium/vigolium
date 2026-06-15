package cdn_object_traversal_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cdn-object-traversal-listing"
	ModuleName  = "CDN Object-Storage Traversal Listing"
	ModuleShort = "Detects bucket object enumeration via ..; path traversal on CDN-fronted object storage"
)

var (
	ModuleDesc = `**What it means:** Appending a parent-directory traversal segment to an object's path on CDN-fronted cloud storage (GCS, S3-compatible, TOS/OSS) turns a file fetch into a full bucket listing, exposing keys never meant to be discoverable.

**How it's exploited:** An attacker appends ..; (or encoded %2e%2e%3b) to a known object URL; the CDN forwards the segment while the backend collapses it and falls back from GetObject to ListObjects. Leaked key names reveal backups and private uploads to fetch directly.

**Fix:** Reject and canonicalize non-standard path segments at the CDN/gateway, and disable anonymous bucket listing.`

	ModuleConfirmation = "Confirmed when a ..;-family trailing payload turns an object fetch into a bucket listing absent from the stable baseline, a non-collapsing control does not list, and the listing reproduces."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "cloud-storage", "path-traversal", "info-disclosure", "light"}
)
