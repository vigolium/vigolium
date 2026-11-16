package infra

import (
	"fmt"
	"sync"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

var (
	ErrRateLimited       = fmt.Errorf("rate limited")
	ErrCloudflareCaptcha = fmt.Errorf("cloudflare captcha")
	ErrAkamaiIPBlocked   = fmt.Errorf("akamai IP address blocked")
	ErrCloudFrontError   = fmt.Errorf("amazon cloudfront error")
	ErrIncapsulaError    = fmt.Errorf("imperva incapsula error")
	ErrAwsElbError       = fmt.Errorf("aws elb error")
	ErrChallengePage     = fmt.Errorf("interactive WAF/CDN challenge page")
)

// ChallengeBodyMarkers are byte needles that appear only on interstitial
// WAF/CDN challenge ("checking your browser") pages, never in a genuine
// application response. They let the detector catch a challenge the edge serves
// with an ordinary 200/202 status — Cloudflare managed and JS challenges
// routinely do — which the status-code gate alone would pass through and feed to
// a body-matching module (the motivating false positive: a Cloudflare challenge
// whose random per-request tokens happened to contain "TiKV" was reported as
// error-based SQLi). Each marker is specific enough that a real app body cannot
// plausibly contain it: a login page that merely embeds a Turnstile widget
// carries "challenges.cloudflare.com" but none of these, so it is not flagged.
//
// Exported because modkit's edge-block detector (IsEdgeBlockedResponse) reuses
// the same set — one source of truth, so a new challenge string is added in one
// place, not two. Per-vendor block-page markers, which count only beside that
// vendor's presence header, live in waf.EdgeBlockPage's table.
var ChallengeBodyMarkers = [][]byte{
	[]byte("_cf_chl_opt"),                               // Cloudflare challenge opt object (window._cf_chl_opt)
	[]byte("/cdn-cgi/challenge-platform/"),              // Cloudflare challenge orchestration script
	[]byte("Enable JavaScript and cookies to continue"), // Cloudflare managed/JS-challenge noscript text
	[]byte("_Incapsula_Resource"),                       // Imperva Incapsula interstitial
	[]byte("Request unsuccessful. Incapsula incident"),  // Imperva Incapsula block page
	// Netlify bot-protection interstitial: the proof-of-work challenge page posts
	// its solution to /.netlify/submit-challenge. The page's inline script emits
	// the path JSON-escaped ("\/.netlify\/submit-challenge"), so both the escaped
	// and plain forms are listed — the needles are raw bytes, and the escaped form
	// is not a substring of the plain one. The reserved /.netlify/ function
	// namespace makes either unambiguous; matching the bare "submit-challenge"
	// action name instead would misfire on a coding-challenge or CTF application.
	[]byte(`\/.netlify\/submit-challenge`),
	[]byte("/.netlify/submit-challenge"),
}

// challengeBodyMatcher is the single-pass form of ChallengeBodyMarkers, built
// once so bodyHasChallengeMarker scans the (capped) body a single time instead of
// once per marker.
var challengeBodyMatcher = NewByteSetMatcher(ChallengeBodyMarkers)

// challengeBodyScanLimit caps how many leading bytes of the body are scanned for
// challenge markers. Interstitial pages carry their markers in the first few KB;
// the cap keeps the check cheap on large application responses.
const challengeBodyScanLimit = 64 << 10

type BlockDetectionValidator struct{}

var (
	defaultValidator *BlockDetectionValidator
	blockDetectOnce  sync.Once
)

// GetBlockDetectionValidator returns the default BlockDetectionValidator instance (lazy loading)
func GetBlockDetectionValidator() *BlockDetectionValidator {
	blockDetectOnce.Do(func() {
		defaultValidator = &BlockDetectionValidator{}
	})
	return defaultValidator
}

// IsBlockedResponse reports whether resp came from a WAF/CDN challenge, auth
// gate, rate limiter, or maintenance page rather than the application. A module
// that flags a vulnerability by matching an error/signature token in the
// response body MUST skip such a response before matching: a denied, throttled,
// or challenged page is not the application surfacing a marker, so any token it
// carries can only be a false positive (the motivating case: a Cloudflare 429 /
// 200 challenge page behind an SSO wall whose random tokens matched a DBMS error
// signature). It combines the vendor-aware detector — which also catches
// status-independent challenge interstitials by header / body marker — with a
// plain status gate for generic WAFs the detector does not recognize.
//
// Do NOT use this in modules whose finding IS a blocking status (e.g. an
// access-control check that treats 403 as the signal); it would suppress the
// very response they look for.
func IsBlockedResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	if GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 401, 403, 429, 503:
		return true
	}
	return false
}

// IsBlockedOrThrottled reports whether resp came from a rate limiter or a
// WAF/CDN edge rather than the application: the vendor-aware block detector
// (a Cloudflare, Akamai, CloudFront, Incapsula or AWS ELB block page, a
// challenge interstitial, Cf-Mitigated, 429) plus the throttling and
// edge-block statuses 408, 425, 429 and 451. Such a response never exercised the
// route, so its body (often an error page reflecting the requested path) cannot
// confirm exposure.
//
// Unlike IsBlockedResponse it does not treat 401/403/503 as blocked, so modules
// whose signal can legitimately be an auth wall keep seeing those responses.
func IsBlockedOrThrottled(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	if GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 408, // request timeout
		425, // too early
		429, // too many requests
		451: // unavailable for legal reasons (edge block)
		return true
	}
	return false
}

// IsErrorSurfaceStatus reports whether resp's status is one an application could
// plausibly use to surface a server-side leak (a DBMS/driver error string, a
// reflected file's contents, a stack trace, an injected marker). A genuine leak
// of that kind rides a 5xx (the stack choked) or a 2xx/4xx the app returns with
// the payload echoed into the body. A 404 means the route never resolved — no
// query/handler ran — and a 3xx redirect carries no handler output, so a
// signature substring in either body is page noise (a catch-all/SPA 404 shell,
// a redirect interstitial), not evidence of the vulnerability.
//
// This is the companion gate to IsBlockedResponse: that one rejects WAF/CDN/
// auth/rate-limit pages (401/403/429/503 + challenge markers), this one rejects
// the no-handler-ran statuses (404 + 3xx) that IsBlockedResponse deliberately
// leaves alone. A body-matching module whose finding is NOT itself a status
// signal should reject a response that fails EITHER gate before matching.
//
// Do NOT use this in a module whose finding IS a 404/redirect (e.g. a broken-link
// or open-redirect check) — it would suppress the very response it looks for.
func IsErrorSurfaceStatus(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	code := resp.Response().StatusCode
	if code == 404 {
		return false
	}
	if code >= 300 && code < 400 {
		return false
	}
	return true
}

func (v *BlockDetectionValidator) Validate(resp *httputil.ResponseChain) error {
	if v == nil || resp == nil || resp.Response() == nil {
		return nil
	}

	header := resp.Response().Header
	statusCode := resp.Response().StatusCode

	switch statusCode {
	case 429:
		return ErrRateLimited
	case 403, 503:
		// A vendor's presence header rides on every response its edge proxies,
		// so on a 403/503 it says only that the edge is in the path: an
		// application's own authorization 403 behind a CDN is the application
		// answering. The edge answered only when the body is that vendor's own
		// block page (waf.EdgeBlockPage, the shared marker table).
		if vendor := waf.EdgeBlockPage(header.Get, scanBody(resp)); vendor != "" {
			return edgeVendorErrors[vendor]
		}
	}

	// Status-independent challenge detection. Cloudflare stamps "cf-mitigated"
	// on any response where it issued a challenge or block — including ones it
	// returns with a 200/202 the status switch above would let through. The
	// body-marker scan is the backstop for edges that serve a challenge without
	// the header. Either signal means the response came from the edge, not the
	// application, so a body-matching module must not read it as app output.
	if header.Get("Cf-Mitigated") != "" {
		return ErrChallengePage
	}
	if bodyHasChallengeMarker(resp) {
		return ErrChallengePage
	}

	return nil
}

// edgeVendorErrors maps an edge vendor waf.EdgeBlockPage names to the error
// Validate returns for its block page.
var edgeVendorErrors = map[string]error{
	"cloudflare": ErrCloudflareCaptcha,
	"akamai":     ErrAkamaiIPBlocked,
	"cloudfront": ErrCloudFrontError,
	"imperva":    ErrIncapsulaError,
	"awselb":     ErrAwsElbError,
}

// bodyHasChallengeMarker reports whether the (capped) response body contains an
// interstitial WAF/CDN challenge marker.
func bodyHasChallengeMarker(resp *httputil.ResponseChain) bool {
	return challengeBodyMatcher.MatchAny(scanBody(resp))
}

// scanBody is the leading challengeBodyScanLimit bytes of the response body,
// read in place and not retained, so it stays valid for the lifetime of the
// caller's call.
func scanBody(resp *httputil.ResponseChain) []byte {
	body := resp.Body()
	if body == nil || body.Len() == 0 {
		return nil
	}
	b := body.Bytes()
	if len(b) > challengeBodyScanLimit {
		b = b[:challengeBodyScanLimit]
	}
	return b
}
