package firebase_functions_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-functions-exposure"
	ModuleName  = "Firebase Functions Exposure"
	ModuleShort = "Detects unauthenticated Firebase Cloud Functions and verbose error leakage"
)

var (
	ModuleDesc = `**What it means:** Firebase Cloud Functions (cloudfunctions.net) whose URLs appear in page or JavaScript responses either return real data to anonymous requests or leak verbose errors, disclosing business data and internals.

**How it's exploited:** An attacker harvests the URLs from front-end code and calls them directly without any login. Malformed JSON can surface stack traces, internal /workspace and node_modules paths, and runtime versions that map the backend.

**Fix:** Require authentication or App Check on every callable and HTTP function, restrict access with IAM, and disable verbose error output.`

	ModuleConfirmation = "Confirmed when Cloud Function endpoints respond with business data without authentication or leak stack traces"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "info-disclosure", "probe", "moderate"}
)
