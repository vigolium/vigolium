package diffscan

import (
	"bytes"
	defaulthttputil "net/http/httputil"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/anomaly"
)

// ResponseSnapshot contains extracted data from a ResponseChain.
// It is designed to be created immediately after an HTTP request,
// allowing the ResponseChain to be closed and its buffers returned to the pool.
type ResponseSnapshot struct {
	// Filtered response for keyword tracking and anchor reflection counting
	FilteredResponse []byte

	// Full fingerprint for structural comparison (replaces FastResponseVariations + QuantFingerprint)
	Fingerprint *anomaly.Fingerprint

	// WAF detection metadata
	StatusCode int

	// Report generation metadata
	RequestDump   string
	ContentLength int
	URL           string
	Method        string
}

// NewResponseSnapshot creates a snapshot from a ResponseChain.
// IMPORTANT: This function closes the ResponseChain after extracting data.
// The caller should NOT use the ResponseChain after calling this function.
func NewResponseSnapshot(respChain *httputil.ResponseChain) *ResponseSnapshot {
	if respChain == nil || !respChain.Has() {
		return nil
	}

	snap := &ResponseSnapshot{}

	// 1. WAF detection metadata
	resp := respChain.Response()
	snap.StatusCode = resp.StatusCode

	// 2. Report metadata
	if req := respChain.Request(); req != nil {
		snap.URL = req.URL.String()
		snap.Method = req.Method
		if rawReq, err := defaulthttputil.DumpRequest(req, true); err == nil {
			snap.RequestDump = string(rawReq)
		}
	}
	snap.ContentLength = respChain.Body().Len()

	// 3. Fingerprinting data (copy because buffer will be returned to pool)
	snap.FilteredResponse = filterResponse(respChain)

	// 4. Full structural fingerprint
	snap.Fingerprint = anomaly.NewFingerprint2(resp.StatusCode, respChain.Body().String(), resp.Header, diffScanFingerprintTypes)

	// 5. Close ResponseChain immediately - return buffers to pool
	respChain.Close()

	return snap
}

// filterResponse extracts and normalizes response data based on content type.
func filterResponse(response *httputil.ResponseChain) []byte {
	if response == nil || !response.Has() {
		return []byte("null")
	}

	var filteredResponse []byte
	mime := anomaly.NewMimetypeDetector2(response)

	if mime.Is(
		anomaly.ContentTypeText,
		anomaly.ContentTypeHTML,
		anomaly.ContentTypeCSS,
		anomaly.ContentTypeXML,
	) {
		filteredResponse = bytes.ToLower(response.FullResponseBytes())
	} else if mime.Is(anomaly.ContentTypeJSON, anomaly.ContentTypeScript) {
		headers := response.Headers().String()
		body := response.Body().String()
		unescapedBody := unescapeJSON(body)
		filteredResponse = []byte(headers + unescapedBody)
	} else {
		headers := response.Headers().String()
		mimeStr := mime.GetInferredMimeType().String()
		filteredResponse = bytes.ToLower([]byte(headers + mimeStr))
	}

	// Make a copy since the original buffer will be returned to pool
	result := make([]byte, len(filteredResponse))
	copy(result, filteredResponse)
	return result
}

// Handles: \\ → \, \" → ", \' → ', \n → newline, \r → CR, \t → tab, \/ → /
func unescapeJSON(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}

	var result strings.Builder
	result.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				result.WriteByte('\\')
				i += 2
			case '"':
				result.WriteByte('"')
				i += 2
			case '\'':
				result.WriteByte('\'')
				i += 2
			case 'n':
				result.WriteByte('\n')
				i += 2
			case 'r':
				result.WriteByte('\r')
				i += 2
			case 't':
				result.WriteByte('\t')
				i += 2
			case '/':
				result.WriteByte('/')
				i += 2
			case 'b':
				result.WriteByte('\b')
				i += 2
			case 'f':
				result.WriteByte('\f')
				i += 2
			case 'u':
				// Handle \uXXXX unicode escapes
				if i+5 < len(s) {
					if r := parseHexRune(s[i+2 : i+6]); r >= 0 {
						result.WriteRune(r)
						i += 6
						continue
					}
				}
				result.WriteByte(s[i])
				i++
			default:
				result.WriteByte(s[i])
				i++
			}
		} else {
			result.WriteByte(s[i])
			i++
		}
	}

	return result.String()
}

// parseHexRune parses a 4-character hex string into a rune.
// Returns -1 if parsing fails.
func parseHexRune(hex string) rune {
	if len(hex) != 4 {
		return -1
	}
	var r rune
	for _, c := range hex {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return -1
		}
	}
	return r
}

// WafBlocked reports whether the response is a denial / throttle / unavailable
// page — a WAF/CDN/auth/rate-limit layer rejecting the request — rather than the
// application actually processing the injected payload. Diff-based detection
// keys off how the app *reacts* to a payload, so a response that never reached
// the app is not a vulnerability signal and must not count as a "diff".
//
// Any 401/403/429/503 is treated as blocked regardless of vendor: the previous
// vendor-gated check (cloudflare/akamai/cloudfront/incapsula only) let a generic
// app/proxy 403 "Forbidden", 401 auth challenge, or 503 maintenance page slip
// through as a payload-driven difference — the reported diff-based false
// positive. A 5xx *application* error such as 500 is deliberately NOT treated as
// blocked: error-based SSTI/behaviour detection legitimately relies on it.
func (s *ResponseSnapshot) WafBlocked() bool {
	if s == nil {
		return false
	}

	switch s.StatusCode {
	case 401, 403, 429, 503:
		return true
	}

	return false
}

// IsSuccess reports whether the response is a 2xx success — i.e. the server
// actually served a real resource rather than an error/not-found/redirect stub.
//
// Diff-based path-escape and normalization detection compares how the server
// resolves a "control" path that should reach a genuine resource against an
// exploit path. When the reached side is a 4xx/5xx (e.g. an empty 404 emitted
// for everything under a CDN-internal prefix like /cdn-cgi/) or a 3xx, nothing
// was actually reached: any break-vs-escape difference is header jitter
// (Ray-ID / ETag / Date / Set-Cookie), not evidence of a path escape. Callers
// gate on this to require the reached resource be a served 2xx body. (WafBlocked
// already drops 401/403/429/503; this is the complementary "did we reach a real
// resource" check that also excludes 404/3xx/5xx.)
func (s *ResponseSnapshot) IsSuccess() bool {
	if s == nil {
		return false
	}
	return s.StatusCode >= 200 && s.StatusCode < 300
}

// IsRedirect reports whether the response is an HTTP redirect (3xx).
//
// A redirect carries no observable evidence of how the application *processed*
// an injected payload: the body is a fixed stub and the only payload-dependent
// part is the echoed Location header. Diff-based, error-based detection
// (SSTI / behaviour probing) therefore cannot use a redirect as an evaluation
// signal — a break-vs-escape difference between two redirects is the literal
// payload being reflected back into the redirect target, not the template
// engine evaluating it. This was the source of the reported diff-based SSTI
// false positives on identity/CIAM hosts that 301-redirect every request:
// break `{{7/0}}` and escape `{{7/1}}` produced identical 301s with identical
// body length, differing only in the CRC32 of the echoed Location header.
//
// A status *transition* (e.g. 200 → 301) is still a legitimate signal: it
// shows up in the STATUS_CODE fingerprint attribute, and at least one side of
// the comparison is not a redirect, so it is never suppressed by this gate.
func (s *ResponseSnapshot) IsRedirect() bool {
	if s == nil {
		return false
	}
	return s.StatusCode >= 300 && s.StatusCode < 400
}

// IsEmptyBody reports whether the response carried no body. Error-based,
// diff-based detection needs the payload to reach something that produces
// output: when a confirmed response has a 0-length body there is nothing
// rendered that could have evaluated the payload, so a break-vs-escape
// difference across empty responses can only be header/cookie jitter, not
// template evaluation.
func (s *ResponseSnapshot) IsEmptyBody() bool {
	return s != nil && s.ContentLength == 0
}

// IsNotFound reports whether the response is a 404. A pair of 404s means the
// route/template was never reached — in most stacks the router rejects the path
// before any template layer runs — so a difference between two 404s is not
// evidence the payload was evaluated. (Reflection into a custom 404 page is
// still caught separately by the body-reflection gate.)
func (s *ResponseSnapshot) IsNotFound() bool {
	return s != nil && s.StatusCode == 404
}
