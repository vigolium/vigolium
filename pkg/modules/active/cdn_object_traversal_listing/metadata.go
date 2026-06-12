package cdn_object_traversal_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cdn-object-traversal-listing"
	ModuleName  = "CDN Object-Storage Traversal Listing"
	ModuleShort = "Detects bucket object enumeration via ..; path traversal on CDN-fronted object storage"
)

var (
	ModuleDesc = `**What it means:** An object on CDN-fronted cloud object storage (GCS, S3-compatible, TOS/OSS) can be turned into a full bucket listing by appending a parent-directory traversal segment to its path. Instead of fetching the single requested file, the storage backend returns an enumeration of every object key in that directory, exposing the names and structure of files that were never meant to be discoverable.

**How it's exploited:** An attacker appends the matrix-parameter form ..; (or an encoded variant such as %2e%2e%3b) to a known object URL. The CDN forwards the non-canonical segment unchanged while the backend collapses it to the parent directory and falls back from GetObject to ListObjects, returning a listing. The leaked key names map the bucket and reveal other tenants' or users' filenames, backups, and private uploads, which the attacker can then request directly to harvest unintended data.

**Fix:** Reject and canonicalize non-standard path segments (including ..; and its encoded forms) at the CDN/gateway, and disable anonymous bucket listing so a parent-directory resolution cannot enumerate objects.`

	ModuleConfirmation = "Confirmed when a ..;-family trailing payload turns an object fetch into a bucket listing absent from the stable baseline, a non-collapsing control does not list, and the listing reproduces."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "cloud-storage", "path-traversal", "info-disclosure", "light"}
)
