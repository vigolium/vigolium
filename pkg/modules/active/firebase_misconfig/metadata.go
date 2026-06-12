package firebase_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-misconfig"
	ModuleName  = "Firebase Misconfiguration"
	ModuleShort = "Detects exposed Firebase configuration, security rules, and credential files"
)

var (
	ModuleDesc = `**What it means:** A Firebase-specific file or endpoint that should not be publicly reachable is being served by the host. Depending on which file leaked, this ranges from informational project-config disclosure (init.json, google-services.json, GoogleService-Info.plist) up to exposure of Firestore/Storage/Realtime Database security rules, Cloud Functions runtime config, or an Admin SDK service account key with embedded private_key material.

**How it's exploited:** Leaked security rules reveal the authorization logic, letting an attacker craft requests that exploit overly permissive read/write paths against the live backend. Leaked runtime config often contains third-party API keys and credentials, and a leaked service account key grants full programmatic admin access to the Firebase project and its Google Cloud resources, enabling data theft, modification, and account takeover.

**Fix:** Remove these files from the web root and any public hosting deploy, store credentials and runtime config in a secret manager outside the served tree, and rotate any service account key, API key, or credential that was exposed.`

	ModuleConfirmation = "Confirmed when probed Firebase files return 200 with expected content markers (Firebase config keys, rules syntax, service account fields)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "sensitive-file", "moderate"}
)
