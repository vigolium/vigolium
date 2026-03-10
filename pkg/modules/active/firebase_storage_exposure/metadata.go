package firebase_storage_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-storage-exposure"
	ModuleName  = "Firebase Storage Exposure"
	ModuleShort = "Detects publicly accessible Firebase Cloud Storage buckets"
)

var (
	ModuleDesc = `## Description
Extracts Firebase Storage bucket names from crawled responses and probes
them for public listing and access via the Firebase Storage REST API
and Google Cloud Storage endpoints.

## Notes
- Extracts storageBucket from Firebase config in HTML/JS responses
- Tests object listing via Firebase Storage REST API
- Probes common prefixes: users/, uploads/, exports/, backups/
- Tests Google Cloud Storage endpoint for alternative public access
- Non-destructive: all probes are read-only GET requests
- Deduplicates by bucket name to avoid redundant probing

## References
- https://firebase.google.com/docs/storage/web/start
- https://firebase.google.com/docs/storage/security`

	ModuleConfirmation = "Confirmed when Firebase Storage listing endpoint returns HTTP 200 with items or prefixes in JSON response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "cloud", "info-disclosure", "moderate"}
)
