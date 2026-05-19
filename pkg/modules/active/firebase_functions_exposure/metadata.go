package firebase_functions_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-functions-exposure"
	ModuleName  = "Firebase Functions Exposure"
	ModuleShort = "Detects unauthenticated Firebase Cloud Functions and verbose error leakage"
)

var (
	ModuleDesc = `## Description
Extracts Cloud Functions URLs from crawled responses and probes them for
unauthenticated access and verbose error leakage.

## Notes
- Extracts cloudfunctions.net URLs from HTML/JS responses
- Parses firebase.json hosting rewrites if available to discover function routes
- Probes discovered functions without authentication
- Tests for verbose error/stack trace leakage with malformed input
- Non-destructive: uses GET and safe POST probes only
- Deduplicates by function URL to avoid redundant probing

## References
- https://firebase.google.com/docs/functions/http-events
- https://firebase.google.com/docs/hosting/cloud-functions`

	ModuleConfirmation = "Confirmed when Cloud Function endpoints respond with business data without authentication or leak stack traces"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "info-disclosure", "probe", "moderate"}
)
