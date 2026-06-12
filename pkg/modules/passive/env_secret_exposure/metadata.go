package env_secret_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "env-secret-exposure"
	ModuleName  = "Environment Secret Exposure"
	ModuleShort = "Detects secrets exposed through public environment variables"
)

var (
	ModuleDesc = `**What it means:** A secret value (an API key, token, password, or credential) is shipped to the browser in the application response. This passive check spotted either a framework public environment variable (NEXT_PUBLIC_, VITE_, or REACT_APP_ prefix whose name contains SECRET, KEY, TOKEN, PASSWORD, PRIVATE, or CREDENTIAL) assigned a real value, or a raw .env config file served directly with credential indicators such as sk_live_, AKIA, or ghp_. Because these values reach every client, the secret is publicly disclosed.

**How it's exploited:** An attacker simply opens the page source or JS bundle, reads the exposed secret, and uses it to authenticate to the backing service (payment, cloud, source-control, or database), enabling account takeover, data theft, or charges against the victim's account. No special tooling is needed.

**Fix:** Rotate the leaked secret immediately, keep secrets server-side only (never under a public client prefix or in a web-served .env), and block .env files from being served.`

	ModuleConfirmation = "Confirmed when response body contains public environment variables with secret values or .env file content with credential indicators"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
