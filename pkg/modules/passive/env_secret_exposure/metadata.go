package env_secret_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "env-secret-exposure"
	ModuleName  = "Environment Secret Exposure"
	ModuleShort = "Detects secrets exposed through public environment variables"
)

var (
	ModuleDesc = `**What it means:** A secret (API key, token, password) is shipped to the browser - either a framework public env var (NEXT_PUBLIC_, VITE_, or REACT_APP_ prefix naming a SECRET or KEY) with a real value, or a served .env file with credential indicators. These reach every client, so the secret is disclosed.

**How it's exploited:** An attacker reads the secret from page source or the JS bundle and authenticates to the backing service, enabling takeover and data theft.

**Fix:** Rotate the secret immediately, keep secrets server-side only (never under a public prefix or web-served .env), and stop serving .env files.`

	ModuleConfirmation = "Confirmed when response body contains public environment variables with secret values or .env file content with credential indicators"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
