package firebase_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-misconfig"
	ModuleName  = "Firebase Misconfiguration"
	ModuleShort = "Detects exposed Firebase configuration, security rules, and credential files"
)

var (
	ModuleDesc = `## Description
Probes for Firebase-specific files and endpoints that should not be publicly
accessible: project configuration, security rules, runtime config, service
account keys, and mobile config files.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Checks /__/firebase/init.json for project config exposure
- Probes for security rules files (firestore.rules, storage.rules, database.rules.json)
- Detects exposed service account keys and runtime configuration
- Non-destructive: all probes are read-only GET requests

## References
- https://firebase.google.com/docs/hosting/reserved-urls
- https://firebase.google.com/docs/rules
- https://firebase.google.com/docs/admin/setup`

	ModuleConfirmation = "Confirmed when probed Firebase files return 200 with expected content markers (Firebase config keys, rules syntax, service account fields)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "sensitive-file", "moderate"}
)
