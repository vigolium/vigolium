package infra

import "strings"

// knownSessionCookies are exact cookie names used for server-side sessions across
// common frameworks. A name here (or any name containing "sess") is a session
// cookie.
var knownSessionCookies = map[string]struct{}{
	"sessionid": {}, "jsessionid": {}, "phpsessid": {}, "asp.net_sessionid": {},
	"aspsessionid": {}, "connect.sid": {}, "laravel_session": {}, "ci_session": {},
	"sid": {}, "sails.sid": {}, "session": {}, "_session_id": {}, "session_id": {},
	"cfid": {}, "cftoken": {}, "symfony": {},
}

// IsSessionCookieName reports whether name denotes a server-side session cookie —
// a known framework session name or any name containing "sess". Shared so session
// and auth-aware modules recognize session cookies consistently.
func IsSessionCookieName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, ok := knownSessionCookies[n]; ok {
		return true
	}
	return strings.Contains(n, "sess")
}
