package firebase_rtdb_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-rtdb-exposure"
	ModuleName  = "Firebase RTDB Exposure"
	ModuleShort = "Detects publicly readable Firebase Realtime Database instances"
)

var (
	ModuleDesc = `**What it means:** A Firebase Realtime Database referenced by the application is publicly readable over its REST API, meaning anyone can fetch its stored data without authentication. The module extracts the database URL from the page or JavaScript, then confirms exposure by retrieving genuine JSON data (a non-empty object or array, not a permission-denied or error response) from the database root or a common subpath such as users, admin, tokens, or accounts.

**How it's exploited:** An attacker requests the database JSON endpoint directly (for example database.firebaseio.com/.json) and downloads the entire data tree or readable branches, harvesting user records, credentials, and configuration. When the scanner spots embedded secrets such as JWTs, Google API keys, Stripe keys, Slack tokens, or private keys in the exposed data, those can be reused immediately to escalate access. Misconfigured rules often also allow writes, enabling data tampering.

**Fix:** Set Firebase security rules so reads (and writes) require authentication and authorization instead of allowing public access, and rotate any secrets that were exposed in the database.`

	ModuleConfirmation = "Confirmed when Firebase RTDB REST endpoint returns HTTP 200 with JSON data instead of permission denied"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "info-disclosure", "moderate"}
)
