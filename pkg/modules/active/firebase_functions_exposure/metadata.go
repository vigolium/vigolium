package firebase_functions_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-functions-exposure"
	ModuleName  = "Firebase Functions Exposure"
	ModuleShort = "Detects unauthenticated Firebase Cloud Functions and verbose error leakage"
)

var (
	ModuleDesc = `**What it means:** The application exposes one or more Firebase Cloud Functions (cloudfunctions.net endpoints) whose URLs were found in page or JavaScript responses, and at least one of those functions either returns real data to anonymous requests or leaks verbose error details. An internet-facing function that serves business data without authentication, or that returns stack traces and internal file paths on malformed input, discloses sensitive information and internal implementation detail.

**How it's exploited:** An attacker harvests the function URLs straight from the front-end code and calls them directly, retrieving the data or invoking the logic the function exposes without any login or token. Sending malformed JSON can surface stack traces, internal /workspace and node_modules paths, and runtime versions that help map the backend and target further attacks.

**Fix:** Require authentication or App Check on every callable and HTTP Cloud Function, restrict access with IAM, and disable verbose error output so malformed input returns a generic error instead of stack traces.`

	ModuleConfirmation = "Confirmed when Cloud Function endpoints respond with business data without authentication or leak stack traces"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "info-disclosure", "probe", "moderate"}
)
