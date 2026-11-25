package modkit

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// edgeBlockBodyScanLimit caps how many leading body bytes the classifier reads.
// Block and challenge pages carry their markers in the first few KB; the cap
// keeps the check cheap on large application responses.
const edgeBlockBodyScanLimit = 16 << 10

// IsEdgeBlockedResponse reports whether resp came from a WAF/CDN edge block or
// interstitial challenge rather than the application. It is the passive-module
// counterpart to infra.IsBlockedResponse, which requires a *httputil.ResponseChain
// that passive modules do not hold: this works against the raw httpmsg response,
// through the same signature table (waf.ClassifyResponse).
//
// A content/value-leak detector that flags a secret, token, version string,
// stack trace, or sensitive field by matching the RESPONSE body or headers MUST
// skip such a response: a denied/challenged page is the edge talking, not the
// application, so any token it carries can only be a false positive (the
// motivating case: an "Authorization" finding on a CloudFront "Request blocked"
// 403, and the broader Cloudflare-challenge-token-as-SQLi class).
//
// A CDN's presence is not a block. Cloudflare stamps Server: cloudflare on every
// response it proxies, and Akamai, CloudFront, ELB and Incapsula identify
// themselves on proxied responses too, so a block status behind one of them is
// an edge block only when a vendor block or challenge row fires — a vendor
// block-page marker beside the vendor's header, a vendor stamp, a challenge
// page. An application's own authorization 403 behind a CDN is the application
// answering — the response an access-control test and the param miner need to
// see — and is not suppressed. A generic application 401/403 is never a block.
// Do NOT use this in a module whose finding IS a blocking status (an
// access-control 403 check) — it would suppress an edge-rendered one.
func IsEdgeBlockedResponse(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	status := resp.StatusCode()
	if status == 429 {
		return true
	}
	if !waf.IsCandidateStatusCode(status) {
		return false
	}
	body := resp.Body()
	if len(body) > edgeBlockBodyScanLimit {
		body = body[:edgeBlockBodyScanLimit]
	}
	header := http.Header{}
	for _, h := range resp.Headers() {
		header.Add(h.Name, h.Value)
	}
	switch waf.ClassifyResponse(status, header, body).Kind() {
	case waf.KindVendor, waf.KindChallenge:
		return true
	}
	return false
}
