package firebase_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-misconfig"
	ModuleName  = "Firebase Misconfiguration"
	ModuleShort = "Detects exposed Firebase configuration, security rules, and credential files"
)

var (
	ModuleDesc = `**What it means:** The host serves a Firebase file that should not be public, ranging from project-config disclosure (init.json, google-services.json) up to leaked Firestore/Storage/RTDB security rules, runtime config, or an Admin SDK service account key with private_key.

**How it's exploited:** Leaked rules reveal authorization logic, letting an attacker exploit permissive read/write paths. Runtime config holds third-party keys, and a service account key grants full admin access to the project and its Google Cloud resources.

**Fix:** Remove these files from the web root and deploys, store credentials in a secret manager outside the served tree, and rotate any exposed key.`

	ModuleConfirmation = "Confirmed when probed Firebase files return 200 with expected content markers (Firebase config keys, rules syntax, service account fields)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "sensitive-file", "moderate"}
)
