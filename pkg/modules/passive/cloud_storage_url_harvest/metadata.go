package cloud_storage_url_harvest

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-url-harvest"
	ModuleName  = "Cloud Storage URL Harvester"
	ModuleShort = "Harvests object-storage/CDN object URLs from page bodies and queues them for traversal probing"
)

var (
	ModuleDesc = `**What it means:** The application's HTML, JS, or JSON responses reference object-storage URLs (vanity-CDN /obj/<bucket>/<object> shapes plus AWS S3 and Google Cloud Storage endpoints). This is an informational discovery result: it surfaces which cloud buckets the site relies on and expands the attack surface available for further testing. It is not itself a vulnerability.

**How it's exploited:** The disclosed bucket and object paths map the application's cloud-storage footprint, telling an attacker which buckets to target for misconfiguration, public-listing, or path-traversal probing. Vigolium queues a GET against each newly-seen bucket so the active CDN object-storage traversal module can test whether sibling or out-of-scope objects are reachable; any real impact is reported by that downstream module, not here.

**Fix:** Treat referenced bucket and object paths as exposed; ensure storage buckets enforce least-privilege access controls, disable public listing, and serve content only through scoped, signed URLs.`

	ModuleConfirmation = "Informational: lists object-storage object URLs discovered in response bodies and queued for active probing."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "cloud-storage", "discovery", "passive", "light"}
)
