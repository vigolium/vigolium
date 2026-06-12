package firebase_auth_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "firebase-auth-misconfig"
	ModuleName  = "Firebase Auth Misconfiguration"
	ModuleShort = "Detects Firebase Authentication misconfigurations via Identity Toolkit probing"
)

var (
	ModuleDesc = `**What it means:** The application exposes a Firebase apiKey in its HTML or JavaScript, and the linked Firebase Identity Toolkit project is misconfigured in at least one way: anonymous sign-in is enabled (anyone gets an authenticated token without a real identity), the login endpoint returns distinguishable errors that confirm which emails are registered, or the createAuthUri endpoint reveals whether an account exists and which auth providers it uses. These weaken the trust boundary of Firebase Authentication.

**How it's exploited:** An attacker reuses the public API key against identitytoolkit.googleapis.com to mint anonymous tokens that may satisfy auth != null security rules and reach protected Firestore or Storage data, and to enumerate or correlate valid user accounts (existence and linked sign-in providers) for targeted phishing, credential stuffing, or account-takeover attempts.

**Fix:** Disable anonymous sign-in if unused, enable Firebase email-enumeration protection so error responses are uniform, restrict the API key by referrer or app, and enforce strict Firestore/Storage security rules that do not trust anonymous accounts.`

	ModuleConfirmation = "Confirmed when Identity Toolkit endpoints respond with auth tokens or distinguishable error codes indicating misconfiguration"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"firebase", "misconfiguration", "auth-bypass", "moderate"}
)
