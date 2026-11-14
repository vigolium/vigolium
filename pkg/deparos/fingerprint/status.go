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
// "Forbidden") are ordinary application answers too, so an edge block here
// needs a vendor HEADER on a block status, and the body is not consulted.
func IsThrottledResponse(status int, header http.Header, _ []byte) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	// ClassifyParts gates on waf.IsBlockStatusCode itself.
	block := waf.ClassifyParts(status, header, nil)
	return block != nil && block.WAFType != "generic"
}
