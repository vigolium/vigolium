// Package safety holds the shared "never touch this" patterns every crawler,
// form submitter and click explorer consults, so the browser crawl, the
// discovery spider and the in-page JavaScript guards agree on what a
// destructive or session-ending control looks like.
package safety

import (
	"regexp"
	"strings"
)

// LogoutPattern matches names that end the session: link text, hrefs, ARIA
// labels and form actions such as "Log out", "/signout", "log-off". The
// source is valid in both Go RE2 and JavaScript (use JSRegexLiteral).
const LogoutPattern = `log\s*out|sign\s*out|logout|signout|log[-_\s]?off|sign[-_\s]?off|end\s*session`

// DestructivePattern matches names that end the session or mutate state
// irreversibly: logout, delete, destroy, remove, deactivate, unsubscribe,
// close/cancel account. "remove" is anchored on a non-letter so "removed" in a
// path segment like /removed-items is still matched but "unremovable" is not.
const DestructivePattern = LogoutPattern +
	`|delete|destroy|(?:^|[^a-z])remove|deactivate|unsubscribe|close[-_\s]?account|cancel[-_\s]?account|terminate[-_\s]?account`

// DestructiveNameRe is DestructivePattern compiled case-insensitively.
var DestructiveNameRe = regexp.MustCompile(`(?i)` + DestructivePattern)

// LogoutRe is LogoutPattern compiled case-insensitively.
var LogoutRe = regexp.MustCompile(`(?i)` + LogoutPattern)

// IsDestructiveName reports whether any of names reads as destructive.
func IsDestructiveName(names ...string) bool {
	for _, n := range names {
		if n != "" && DestructiveNameRe.MatchString(n) {
			return true
		}
	}
	return false
}

// IsLogoutName reports whether any of names reads as ending the session.
func IsLogoutName(names ...string) bool {
	for _, n := range names {
		if n != "" && LogoutRe.MatchString(n) {
			return true
		}
	}
	return false
}

// JSRegexLiteral renders pattern as a case-insensitive JavaScript regex
// literal (/…/i) for in-page scripts.
func JSRegexLiteral(pattern string) string {
	return "/" + strings.ReplaceAll(pattern, "/", `\/`) + "/i"
}
