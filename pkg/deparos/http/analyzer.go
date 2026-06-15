package http

import (
	"context"
	nethttp "net/http"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// FingerprintComparator defines the interface for fingerprint comparison.
// This allows mocking in tests.
type FingerprintComparator interface {
	Compare(ctx context.Context, req *nethttp.Request, rc *responsechain.ResponseChain) (fingerprint.MatchResult, error)
}

// Analyzer analyzes HTTP responses to determine if resources exist.
// Uses fingerprint comparison for soft 404 detection.
type Analyzer struct {
	comparator FingerprintComparator
}

// NewAnalyzer creates a new response analyzer with fingerprint support.
func NewAnalyzer(comparator *fingerprint.Comparator) *Analyzer {
	// Avoid interface-wrapping a nil pointer (nil pointer in interface != nil interface)
	if comparator == nil {
		return &Analyzer{comparator: nil}
	}
	return &Analyzer{
		comparator: comparator,
	}
}

// NewAnalyzerWithComparator creates an analyzer with a custom comparator (for testing).
func NewAnalyzerWithComparator(comparator FingerprintComparator) *Analyzer {
	return &Analyzer{
		comparator: comparator,
	}
}

// Analyze determines if a resource exists based on HTTP response.
// Returns true if resource exists, false if not found (404 or soft-404).
//
// Fingerprint check is performed FIRST for ALL status codes to detect soft-404s.
func (a *Analyzer) Analyze(ctx context.Context, req *nethttp.Request, rc *responsechain.ResponseChain) (bool, error) {
	// STEP 1: Check fingerprint FIRST for ALL status codes
	// This catches soft-404s regardless of status code
	if a.comparator != nil {
		result, err := a.comparator.Compare(ctx, req, rc)
		if err == nil && result == fingerprint.FalsePositive {
			return false, nil // soft-404
		}
	}

	// STEP 2: HTTP 404 is always not found
	if rc.Response().StatusCode == 404 {
		return false, nil
	}

	// STEP 3: Request-shape rejections are not discovered resources. A 400 (e.g.
	// the Jetty/nginx "Ambiguous URI empty segment" page a stray // triggers), 414
	// (URI too long), 421 (misdirected request) or 431 (request headers too large)
	// means the origin refused to route the request by its shape — not that a file
	// exists there. These pages commonly echo the requested URI into the body, so
	// every probed variant would otherwise land as a distinct "discovered" record.
	// (405 Method Not Allowed is deliberately NOT gated: it means the path exists
	// but rejects the method, which is a real discovery signal.)
	switch rc.Response().StatusCode {
	case 400, 414, 421, 431:
		return false, nil
	}

	// STEP 4: Everything else = resource exists
	return true, nil
}
