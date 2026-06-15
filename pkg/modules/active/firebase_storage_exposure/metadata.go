package firebase_storage_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-storage-exposure"
	ModuleName  = "Firebase Storage Exposure"
	ModuleShort = "Detects publicly accessible Firebase Cloud Storage buckets"
)

var (
	ModuleDesc = `**What it means:** A Firebase Cloud Storage bucket referenced by the app (a storageBucket config value or firebasestorage.googleapis.com URL) allows unauthenticated object listing. The check extracted the bucket name and listed its contents, so anyone can enumerate and likely read the files.

**How it's exploited:** An attacker queries the Storage or Google Cloud Storage API to list objects at the root or common prefixes (users/, uploads/, exports/, backups/) and download what is returned, exposing user uploads and backups.

**Fix:** Apply restrictive Storage security rules and Google Cloud Storage IAM requiring authentication and per-user authorization, and never leave buckets world-listable.`

	ModuleConfirmation = "Confirmed when Firebase Storage listing endpoint returns HTTP 200 with items or prefixes in JSON response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "cloud", "info-disclosure", "moderate"}
)
