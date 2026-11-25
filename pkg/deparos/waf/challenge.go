package waf

import "net/http"

// Block kinds (BlockResult.Kind, the waf.block event's block_kind). A consumer
// reads the kind before the vendor: only KindVendor and KindChallenge
// attribute the response to an edge. They follow the firing Signatures row:
// a challenge row gives KindChallenge, a block row KindVendor, a refused row
// KindRefused.
const (
	// KindVendor is a named vendor's block signature (a block row).
	KindVendor = "vendor"
	// KindRefused is a block status matched only by the generic phrase rule
	// ("Forbidden", "Access Denied", …): nothing names an edge, and an
	// application's own 403 reads the same, so it carries no vendor.
	KindRefused = "refused"
	// KindChallenge is a vendor's challenge or interstitial page, on a success
	// status (200, 202) or a block status.
	KindChallenge = "challenge"
)

// Kind classifies a block result for a consumer: challenge, refused (generic
// rule only, no vendor named) or vendor. "" for nil.
func (b *BlockResult) Kind() string {
	switch {
	case b == nil:
		return ""
	case b.Challenge:
		return KindChallenge
	case b.WAFType == "" || b.WAFType == "generic":
		return KindRefused
	default:
		return KindVendor
	}
}

// Vendor is the edge a result names, "" when it names none (KindRefused).
func (b *BlockResult) Vendor() string {
	if b == nil || b.Kind() == KindRefused {
		return ""
	}
	return b.WAFType
}

// IsChallengeStatusCode reports whether code is a success status an edge serves
// its challenge page on: Cloudflare, Imperva and Sucuri answer a JS challenge
// with 200, AWS WAF's challenge action with 202.
func IsChallengeStatusCode(code int) bool {
	return code == http.StatusOK || code == http.StatusAccepted
}

// IsCandidateStatusCode is the pre-gate for ClassifyResponse: every status a
// classifying row of Signatures applies on is one of these.
func IsCandidateStatusCode(code int) bool {
	return IsBlockStatusCode(code) || IsChallengeStatusCode(code)
}
