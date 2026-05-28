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
	StatusCode   int
	ServerHeader string
	CDNHeader    string

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
	snap.ServerHeader = resp.Header.Get("Server")
	snap.CDNHeader = resp.Header.Get("X-CDN")

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

// WafBlocked checks if the response indicates WAF blocking.
func (s *ResponseSnapshot) WafBlocked() bool {
	if s == nil {
		return false
	}

	switch s.StatusCode {
	case 429:
		return true
	case 403:
		switch {
		case len(s.ServerHeader) >= 10 && s.ServerHeader[:10] == "cloudflare":
			return true
		case len(s.ServerHeader) >= 10 && s.ServerHeader[:10] == "AkamaiGHos":
			return true
		case s.ServerHeader == "CloudFront":
			return true
		case s.CDNHeader == "Incapsula":
			return true
		}
	case 503:
		if len(s.ServerHeader) >= 10 && s.ServerHeader[:10] == "cloudflare" {
			return true
		}
	}

	return false
}
