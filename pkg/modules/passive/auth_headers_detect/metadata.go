package auth_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "auth-headers-detect"
	ModuleName  = "Auth Headers Detect"
	ModuleShort = "Detects authorization headers in requests"
)

var (
	ModuleDesc = `**What it means:** Informational: the scanner observed a request carrying an Authorization header (a Bearer token or Basic credentials) and records the endpoint and credential. This marks an authenticated boundary; the credential is sensitive.

**How it's exploited:** The disclosure maps which endpoints need authentication. If the credential is leaked, logged, or sent over a weak channel, an attacker who recovers it replays it to impersonate the user.

**Fix:** Treat Authorization values as secrets: keep them out of logs, caches, and URLs, send only over TLS, scope and expire tokens, and rotate exposed credentials.`

	ModuleConfirmation = "Confirmed when a request carries an Authorization header with a real credential (not a bare scheme or placeholder) and the response is the application, not a WAF/CDN edge block"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "info-disclosure", "light"}
)
