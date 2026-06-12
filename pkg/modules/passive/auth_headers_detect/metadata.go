package auth_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "auth-headers-detect"
	ModuleName  = "Auth Headers Detect"
	ModuleShort = "Detects authorization headers in requests"
)

var (
	ModuleDesc = `**What it means:** This is an informational finding: the scanner passively observed an HTTP request that carries an Authorization header (for example a Bearer token or HTTP Basic credentials) and records the endpoint together with the captured credential value. It marks an authenticated boundary of the application rather than a vulnerability in itself, though the captured token or Basic credential is sensitive and should be handled carefully.

**How it's exploited:** The disclosed information maps which endpoints require authentication and what credential scheme they use, helping an attacker focus on authenticated attack surface. If the underlying token or Basic credential is otherwise leaked, logged, or transmitted over a weak channel, an attacker who recovers it can replay it to impersonate the user and access protected resources.

**Fix:** Treat Authorization values as secrets: keep them out of logs, caches, and URLs, send them only over TLS, scope and expire tokens tightly, and rotate any credential that may have been exposed.`

	ModuleConfirmation = "Confirmed when request contains recognized authentication headers (Authorization, Bearer tokens, API keys)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "info-disclosure", "light"}
)
