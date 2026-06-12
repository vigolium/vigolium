package firebase_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-fingerprint"
	ModuleName  = "Firebase Fingerprint"
	ModuleShort = "Identifies Firebase usage and detects leaked Firebase secrets in responses"
)

var (
	ModuleDesc = `**What it means:** This passive check confirms Google Firebase usage by reading SDK references and the firebaseConfig object from HTML/JS responses, and reports exposed project identifiers (projectId, apiKey, databaseURL, storageBucket, authDomain, appId, Firestore collections, Cloud Functions URLs). Detection itself is informational, but the same pass also flags genuinely sensitive items: leaked FCM server keys, App Check debug tokens, Realtime Database auth tokens, long-lived Storage download tokens, and dev/staging projects used on a production domain.

**How it's exploited:** The disclosed config maps the backend attack surface, letting an attacker probe Firestore/Realtime Database rules, Cloud Functions, and Storage buckets directly with the client SDK. When a real secret leaks, impact escalates: an FCM server key lets an attacker push notifications to all users, an App Check debug token or RTDB auth token grants backend/database access, and Storage tokens expose referenced files.

**Fix:** Treat config as public but enforce strict Firebase rules and App Check, keep server keys and debug/auth/download tokens out of client code, and never ship dev/staging projects to production.`

	ModuleConfirmation = "Confirmed when Firebase SDK references, configuration objects, or leaked Firebase secrets are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "cloud", "fingerprint", "light"}
)
