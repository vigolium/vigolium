package firebase_rtdb_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-rtdb-exposure"
	ModuleName  = "Firebase RTDB Exposure"
	ModuleShort = "Detects publicly readable Firebase Realtime Database instances"
)

var (
	ModuleDesc = `**What it means:** A Firebase Realtime Database referenced by the app is publicly readable over its REST API, so anyone can fetch stored data without authentication. The check extracts the URL and confirms by retrieving genuine JSON.

**How it's exploited:** An attacker requests the JSON endpoint directly (for example database.firebaseio.com/.json) and downloads the data tree, harvesting user records, credentials, and config. Embedded secrets like JWTs or API keys can be reused to escalate. Permissive rules often also allow writes.

**Fix:** Set security rules so reads and writes require authentication and authorization instead of public access, and rotate any exposed secrets.`

	ModuleConfirmation = "Confirmed when Firebase RTDB REST endpoint returns HTTP 200 with JSON data instead of permission denied"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "info-disclosure", "moderate"}
)
