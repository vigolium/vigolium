package firebase_rtdb_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-rtdb-exposure"
	ModuleName  = "Firebase RTDB Exposure"
	ModuleShort = "Detects publicly readable Firebase Realtime Database instances"
)

var (
	ModuleDesc = `**What it means:** An isolated credential-free client reproducibly read a non-empty JSON object or array from a referenced Firebase Realtime Database. Public read alone is a candidate because some datasets are intentionally public.

**How it's exploited:** The result becomes a finding only when returned values include sensitive fields or private credential formats. A shallow list of keys is not full-data exposure, Google client API keys are not secrets, and write access is never inferred.

**Fix:** Set security rules so reads and writes require authentication and authorization instead of public access, and rotate any exposed secrets.`

	ModuleConfirmation = "Candidate requires two credential-free non-empty structured JSON reads; finding additionally requires substantive sensitive fields or private-credential evidence"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"firebase", "info-disclosure", "moderate"}
)
