package env_secret_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "env-secret-exposure"
	ModuleName  = "Environment Secret Exposure"
	ModuleShort = "Detects secrets exposed through public environment variables"
)

var (
	ModuleDesc = `## Description
Scans response bodies for secrets accidentally exposed through public environment
variable mechanisms in modern JS frameworks. Next.js (NEXT_PUBLIC_), Vite (VITE_),
and Create React App (REACT_APP_) all expose prefixed environment variables to the
client bundle. When developers store secret keys, tokens, or passwords in these
public variables, they are shipped to every browser that loads the application.
Also detects .env files served directly with embedded secrets.

## Notes
- Passive only -- does not send any HTTP requests
- Scans JS, HTML, JSON, and plain text responses
- Detects NEXT_PUBLIC_, VITE_, REACT_APP_ prefixed secret variables
- Detects raw .env file content with secret indicators (sk_live_, AKIA, ghp_, etc.)
- Minimum value length of 8 characters to reduce false positives
- Deduplicates by host

## References
- https://nextjs.org/docs/app/building-your-application/configuring/environment-variables
- https://vitejs.dev/guide/env-and-mode.html
- https://create-react-app.dev/docs/adding-custom-environment-variables/
- https://cwe.mitre.org/data/definitions/200.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces`

	ModuleConfirmation = "Confirmed when response body contains public environment variables with secret values or .env file content with credential indicators"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"info-disclosure", "file-exposure", "light"}
)
