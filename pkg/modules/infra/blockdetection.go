package infra

import (
	"fmt"
	"sync"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

var (
	ErrRateLimited = fmt.Errorf("rate limited")
	// ErrEdgeBlock is a named vendor's block page or stamp; the error text
	// names the vendor.
	ErrEdgeBlock = fmt.Errorf("WAF/CDN edge block")
	// ErrChallengePage is a vendor challenge or interstitial page.
	ErrChallengePage = fmt.Errorf("interactive WAF/CDN challenge page")
)

// blockScanLimit caps how many leading bytes of the body the classifier reads.
// Block and challenge pages carry their markers in the first few KB; the cap
// keeps the check cheap on large application responses.
const blockScanLimit = 64 << 10

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
// challenge interstitials served on a 200/202 — with a plain status gate for
// generic WAFs the detector does not recognize.
//
// Do NOT use this in modules whose finding IS a blocking status (e.g. an
// access-control check that treats 403 as the signal); it would suppress the
// very response they look for.
func IsBlockedResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	switch resp.Response().StatusCode {
	case 401, 403, 429, 503:
		return true
	}
	return GetBlockDetectionValidator().Validate(resp) != nil
}

// IsBlockedOrThrottled reports whether resp came from a rate limiter or a
// WAF/CDN edge rather than the application: the vendor-aware block detector
// (a vendor block page or stamp, a challenge interstitial, 429) plus the
// throttling and edge-block statuses 408, 425, 429 and 451. Such a response
// never exercised the route, so its body (often an error page reflecting the
// requested path) cannot confirm exposure.
//
// Unlike IsBlockedResponse it does not treat 401/403/503 as blocked, so modules
// whose signal can legitimately be an auth wall keep seeing those responses.
func IsBlockedOrThrottled(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	switch resp.Response().StatusCode {
	case 408, // request timeout
		425, // too early
		429, // too many requests
		451: // unavailable for legal reasons (edge block)
		return true
	}
	return GetBlockDetectionValidator().Validate(resp) != nil
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

// Validate classifies resp with the shared signature table
// (waf.ClassifyResponse, published as `vigolium schema block-signatures`): a
// 429 is ErrRateLimited, a challenge row ErrChallengePage, a vendor block row
// ErrEdgeBlock. A refused row (a generic phrase on a block status, which an
// application's own 403 says too) is not an edge answer and returns nil; the
// status gates in IsBlockedResponse cover those statuses.
func (v *BlockDetectionValidator) Validate(resp *httputil.ResponseChain) error {
	if v == nil || resp == nil || resp.Response() == nil {
		return nil
	}
	statusCode := resp.Response().StatusCode
	if statusCode == 429 {
		return ErrRateLimited
	}
	block := waf.ClassifyResponse(statusCode, resp.Response().Header, scanBody(resp))
	switch block.Kind() {
	case waf.KindChallenge:
		return fmt.Errorf("%w (%s)", ErrChallengePage, block.Vendor())
	case waf.KindVendor:
		return fmt.Errorf("%w: %s", ErrEdgeBlock, block.Vendor())
	}
	return nil
}

// scanBody is the leading blockScanLimit bytes of the response body, read in
// place and not retained, so it stays valid for the lifetime of the caller's
// call.
func scanBody(resp *httputil.ResponseChain) []byte {
	body := resp.Body()
	if body == nil || body.Len() == 0 {
		return nil
	}
	b := body.Bytes()
	if len(b) > blockScanLimit {
		b = b[:blockScanLimit]
	}
	return b
}
