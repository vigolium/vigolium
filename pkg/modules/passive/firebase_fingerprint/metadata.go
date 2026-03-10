package firebase_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-fingerprint"
	ModuleName  = "Firebase Fingerprint"
	ModuleShort = "Identifies Firebase usage and detects leaked Firebase secrets in responses"
)

var (
	ModuleDesc = `## Description
Passively identifies Firebase usage from HTML/JS responses, extracts project
configuration, and detects leaked Firebase-specific secrets and tokens.

## Notes
- Passive only: does not send any HTTP requests
- Detects Firebase via SDK references, initializeApp calls, and config objects
- Extracts projectId, apiKey, databaseURL, storageBucket from config
- Flags leaked FCM server keys, App Check debug tokens, RTDB auth tokens
- Flags leaked Firebase Storage download tokens in URLs
- Detects staging/dev project indicators in projectId
- Deduplicates by host to avoid redundant processing

## References
- https://firebase.google.com/docs/web/setup
- https://firebase.google.com/docs/projects/api-keys`

	ModuleConfirmation = "Confirmed when Firebase SDK references, configuration objects, or leaked Firebase secrets are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"firebase", "cloud", "fingerprint", "light"}
)
