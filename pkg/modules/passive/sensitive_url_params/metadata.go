package sensitive_url_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-url-params"
	ModuleName  = "Sensitive URL Params"
	ModuleShort = "Detects sensitive data in URL query parameters"
)

var (
	ModuleDesc = `**What it means:** A sensitive value rides in a URL query parameter whose name matches a credential pattern (password, token, api_key, secret, access_token, session_id). URL values are not private: they land in server and proxy logs and browser history, and leak via the Referer header.

**How it's exploited:** Anyone with access to server, CDN, or analytics logs, or a linked site receiving the Referer, harvests the token or key and replays it to authenticate or hijack a session.

**Fix:** Move sensitive values out of the URL into the request body or an Authorization header, and rotate any exposed credential.`

	ModuleConfirmation = "Indicated when URL query parameters contain names or values matching sensitive data patterns (password, token, key, secret)"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
