// Package waf provides WAF/CDN blocking detection implementation.
package waf

import (
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// detector implements Detector over the Signatures table (ClassifyResponse).
type detector struct{}

// NewDetector returns the Signatures-backed detector.
func NewDetector() Detector {
	return detector{}
}

// Detect classifies a response chain with ClassifyResponse. nil when the
// response is not a block or a challenge.
func (detector) Detect(rc *responsechain.ResponseChain) *BlockResult {
	if rc == nil || !rc.Has() {
		return nil
	}
	resp := rc.Response()
	return ClassifyResponse(resp.StatusCode, resp.Header, rc.BodyBytes())
}

// IsBlockStatusCode reports whether code is one WAFs/CDNs commonly use for
// blocking responses. Callers use it as a cheap pre-gate before paying for the
// body read ClassifyResponse needs; every block row's status set lies inside
// it or IsChallengeStatusCode.
func IsBlockStatusCode(code int) bool {
	switch code {
	case 403, 405, 406, 429, 501, 503:
		return true
	}
	// Cloudflare specific codes
	if code >= 520 && code <= 530 {
		return true
	}
	return false
}
