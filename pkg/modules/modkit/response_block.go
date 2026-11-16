package modkit

import (
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// edgeBlockBodyScanLimit caps how many leading body bytes are scanned for edge
// block / challenge markers. Interstitial pages carry their markers in the first
// few KB; the cap keeps the check cheap on large application responses.
const edgeBlockBodyScanLimit = 16 << 10

// edgeBlockBodyMatcher is the single-pass form of the shared challenge set
// (infra.ChallengeBodyMarkers), built once so IsEdgeBlockedResponse scans the
// (capped) body a single time instead of once per marker.
var edgeBlockBodyMatcher = infra.NewByteSetMatcher(infra.ChallengeBodyMarkers)

// IsEdgeBlockedResponse reports whether resp came from a WAF/CDN edge block or
// interstitial challenge rather than the application. It is the passive-module
// counterpart to infra.IsBlockedResponse, which requires a *httputil.ResponseChain
// that passive modules do not hold: this works against the raw httpmsg response
// (status + Cf-Mitigated header + vendor block-page and challenge body markers).
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
// themselves on proxied responses too, so a 4xx/5xx behind one of them is an
// edge block only when its body carries that vendor's block-page signature
// (waf.EdgeBlockPage, the table infra's detector and the WAF rules share) or a
// shared challenge marker. An application's own
// authorization 403 behind a CDN is the application answering — the response
// an access-control test and the param miner need to see — and is not
// suppressed. A generic application 401/403 is never a block. Do NOT use this
// in a module whose finding IS a blocking status (an access-control 403
// check) — it would suppress an edge-rendered one.
func IsEdgeBlockedResponse(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	// Status-independent challenge: Cloudflare stamps this on any response it
	// challenged or blocked, including ones returned with a 200/202.
	if resp.Header("Cf-Mitigated") != "" {
		return true
	}
	if resp.StatusCode() == 429 {
		return true
	}
	body := resp.Body()
	if len(body) > edgeBlockBodyScanLimit {
		body = body[:edgeBlockBodyScanLimit]
	}
	if edgeBlockBodyMatcher.MatchAny(body) {
		return true
	}
	// An edge's own error page rides a 4xx/5xx (CloudFront's 502/504 pages as
	// well as the 403 blocks).
	return resp.StatusCode() >= 400 && waf.EdgeBlockPage(resp.Header, body) != ""
}
