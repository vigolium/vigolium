package firebase_rtdb_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-firebase-rtdb-exposure"
	ModuleName  = "Firebase RTDB Exposure"
	ModuleShort = "Detects publicly readable Firebase Realtime Database instances"
)

var (
	ModuleDesc = `## Description
Extracts Firebase Realtime Database URLs from crawled responses and probes
them for public read access. Tests root-level access and common subpaths
that often contain sensitive data.

## Notes
- Extracts databaseURL from Firebase config in HTML/JS responses
- Probes root with shallow=true for efficient detection
- Tests common subpaths: users, config, admin, tokens, etc.
- Non-destructive: all probes are read-only GET requests
- Scans leaked data for embedded secrets (JWT, API keys)
- Deduplicates by database URL to avoid redundant probing

## References
- https://firebase.google.com/docs/database/rest/start
- https://firebase.google.com/docs/database/security`

	ModuleConfirmation = "Confirmed when Firebase RTDB REST endpoint returns HTTP 200 with JSON data instead of permission denied"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "info-disclosure", "moderate"}
)
