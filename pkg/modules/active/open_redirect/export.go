package open_redirect

import (
	"regexp"

	httpUtils "github.com/projectdiscovery/utils/http"
)

// This file exposes a small, stable surface of this module's proven redirect
// detection so sibling modules (e.g. open_redirect_confusion) can reuse it
// without duplicating the Location/Refresh/meta/JS extraction chain or modifying
// this module's scan flow. The wrappers are thin and behavior-preserving.

// CheckRedirectOutput invokes callback with each redirect target the response
// declares — via the Location header, the Refresh header, a <meta> http-equiv
// refresh/location tag, or a JavaScript location/window redirect. The callback
// returns true to keep scanning further targets, false to stop early.
func CheckRedirectOutput(respChain *httpUtils.ResponseChain, callback func(nextLoc string) bool) {
	checkOutput(respChain, callback)
}

// DomainRedirectRegex returns a regex that matches a redirect target pointing at
// the given domain, covering the https://, //, /\, /\\ and userinfo-prefixed
// forms a redirect value can take.
func DomainRedirectRegex(domain string) *regexp.Regexp {
	return getDomainRedirectRegex(domain)
}

// MatchRedirectParam reports whether a parameter — by its name or its current
// value — looks like a redirect/URL sink worth testing.
func MatchRedirectParam(name, value string) bool {
	return matchTopParams(name) || matchValueIsURL(value)
}
