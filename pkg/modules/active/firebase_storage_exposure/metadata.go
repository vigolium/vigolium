package firebase_storage_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-storage-exposure"
	ModuleName  = "Firebase Storage Exposure"
	ModuleShort = "Detects publicly accessible Firebase Cloud Storage buckets"
)

var (
	ModuleDesc = `**What it means:** A Firebase Cloud Storage bucket referenced by the application (a storageBucket value in its config or a firebasestorage.googleapis.com URL) allows unauthenticated object listing. The module confirmed this by extracting the bucket name from a crawled page and successfully listing its contents, meaning anyone on the internet can enumerate and likely read the stored files.

**How it's exploited:** An attacker reads the same bucket name from the public site, then queries the Firebase Storage REST API or the Google Cloud Storage endpoint to list objects at the root or common prefixes (users/, uploads/, exports/, backups/, private/, documents/) and download whatever is returned. This commonly exposes user uploads, backups, exported data, and other sensitive files, leading to data breach and privacy loss.

**Fix:** Apply restrictive Firebase Storage security rules (and Google Cloud Storage IAM) that require authentication and per-user authorization, and never leave buckets world-readable or world-listable.`

	ModuleConfirmation = "Confirmed when Firebase Storage listing endpoint returns HTTP 200 with items or prefixes in JSON response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "cloud", "info-disclosure", "moderate"}
)
