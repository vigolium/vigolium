package firebase_functions_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-functions-exposure"
	ModuleName  = "Firebase Functions Exposure"
	ModuleShort = "Detects unauthenticated Firebase Cloud Functions and verbose error leakage"
)

var (
	ModuleDesc = `**What it means:** A referenced Firebase Cloud Function returns a stable, function-specific nontrivial response without credentials, or reproducibly exposes multiple payload-introduced stack-trace anchors for malformed JSON.

**How it's exploited:** Public HTTP functions are supported, so response reachability is only a candidate until sensitive data or unauthorized state is proven. Replayed stack traces with clean controls are direct low-severity information disclosure.

**Fix:** Require authentication or App Check on every callable and HTTP function, restrict access with IAM, and disable verbose error output.`

	ModuleConfirmation = "Candidate requires anonymous stable response plus replay and nonexistent-function control; finding requires error status, two introduced stack categories, clean control, and replay"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "info-disclosure", "probe", "moderate"}
)
