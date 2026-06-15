package firebase_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-fingerprint"
	ModuleName  = "Firebase Fingerprint"
	ModuleShort = "Identifies Firebase usage and detects leaked Firebase secrets in responses"
)

var (
	ModuleDesc = `**What it means:** This passive check confirms Firebase usage from SDK references and the firebaseConfig object, reporting exposed identifiers (projectId, apiKey, databaseURL) and sensitive items: leaked FCM server keys, App Check debug tokens, RTDB auth tokens, and Storage tokens.

**How it's exploited:** The disclosed config lets an attacker probe Firestore/RTDB rules and Storage buckets with the client SDK. A leaked FCM key pushes notifications to all users, auth tokens grant backend access, and Storage tokens expose files.

**Fix:** Treat config as public but enforce strict Firebase rules and App Check, and keep server keys and tokens out of client code.`

	ModuleConfirmation = "Confirmed when Firebase SDK references, configuration objects, or leaked Firebase secrets are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "cloud", "fingerprint", "light"}
)
