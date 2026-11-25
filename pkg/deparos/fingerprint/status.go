package fingerprint

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

// IsHardMissStatus reports the statuses that never mean a resource exists:
// 404, and the request-shape rejections 400 (e.g. "Ambiguous URI empty
// segment"), 414 (URI too long), 421 (misdirected) and 431 (headers too
// large). 405 is deliberately absent: it means the path exists but rejects the
// method. pkg/deparos/http re-exports this as IsHardNotFound.
func IsHardMissStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusBadRequest, http.StatusRequestURITooLong,
		http.StatusMisdirectedRequest, http.StatusRequestHeaderFieldsTooLarge:
		return true
	}
	return false
}

// IsThrottledResponse reports a response that says nothing about the probed
// path because the origin or its edge refused to serve it: 429, 503, or a
// vendor-attributed WAF/CDN block page.
//
// Deliberately narrower than the scan requester's block classifier
// (pkg/http.IsBlockedResponse): body phrases alone ("Access Denied",
// "Forbidden") are ordinary application answers too, so the generic rule does
// not count here. A vendor's presence header alone does not either (the WAF
// classifier needs its block page beside it on a 403/503), so an application's
// own 403 behind a CDN is still an answer about the path.
func IsThrottledResponse(status int, header http.Header, body []byte) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	// A vendor block or challenge row; a refused (generic phrase) row is an
	// ordinary application answer here.
	switch waf.ClassifyResponse(status, header, body).Kind() {
	case waf.KindVendor, waf.KindChallenge:
		return true
	}
	return false
}
