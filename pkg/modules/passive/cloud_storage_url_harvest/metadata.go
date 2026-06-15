package cloud_storage_url_harvest

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-url-harvest"
	ModuleName  = "Cloud Storage URL Harvester"
	ModuleShort = "Harvests object-storage/CDN object URLs from page bodies and queues them for traversal probing"
)

var (
	ModuleDesc = `**What it means:** The app's HTML, JS, or JSON responses reference object-storage URLs (vanity-CDN /obj/<bucket>/<object> shapes plus S3 and GCS endpoints). Informational discovery surfacing which cloud buckets the site uses and expanding the testable attack surface.

**How it's exploited:** The disclosed bucket and object paths map the cloud-storage footprint, telling an attacker which buckets to probe. Vigolium queues a GET per new bucket so the active CDN traversal module tests sibling reachability; real impact is reported there.

**Fix:** Treat referenced buckets and paths as exposed; enforce least-privilege access, disable public listing, and serve content only through scoped signed URLs.`

	ModuleConfirmation = "Informational: lists object-storage object URLs discovered in response bodies and queued for active probing."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "cloud-storage", "discovery", "passive", "light"}
)
