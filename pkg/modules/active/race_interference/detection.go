package race_interference

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/anomaly"
)

// ResponseGroup holds a merged fingerprint and associated responses for baseline comparison.
type ResponseGroup struct {
	fingerprint *anomaly.Fingerprint
	statusCode  int
	bodyLength  int
}

// NewResponseGroup creates a new ResponseGroup from initial response data.
func NewResponseGroup(statusCode int, body string, headers map[string][]string) *ResponseGroup {
	fp := anomaly.NewFingerprint2(statusCode, body, headers, fingerprintTypes)
	return &ResponseGroup{
		fingerprint: fp,
		statusCode:  statusCode,
		bodyLength:  len(body),
	}
}

// Update merges another response into the group fingerprint.
func (g *ResponseGroup) Update(statusCode int, body string, headers map[string][]string) {
	g.fingerprint.UpdateWith(statusCode, body, headers)
	// Keep track of latest response metadata
	g.statusCode = statusCode
	g.bodyLength = len(body)
}

// Matches checks if a response matches this baseline group.
func (g *ResponseGroup) Matches(statusCode int, body string, headers map[string][]string) bool {
	other := anomaly.NewFingerprint2(statusCode, body, headers, fingerprintTypes)
	return g.fingerprint.IsSimilar(other)
}

// fingerprintTypes defines which response attributes to use for comparison.
var fingerprintTypes = []anomaly.Type{
	anomaly.STATUS_CODE,
	anomaly.CONTENT_TYPE,
	anomaly.CONTENT_LENGTH,
	anomaly.PAGE_TITLE,
	anomaly.WORD_COUNT,
	anomaly.LINE_COUNT,
	anomaly.LIMITED_BODY_CONTENT,
	anomaly.INITIAL_BODY_CONTENT,
}

// containsWrongId checks if the response body contains the anchor with a different index.
// Returns (hasWrongId, wrongIdFound).
func containsWrongId(body, anchor string, expectedIdx int) (bool, string) {
	// Find all occurrences of anchor in body
	searchFrom := 0
	for {
		idx := strings.Index(body[searchFrom:], anchor)
		if idx == -1 {
			break
		}
		pos := searchFrom + idx + len(anchor)
		searchFrom = pos

		// Check if there's a digit following the anchor
		if pos >= len(body) {
			continue
		}

		// Extract the index digit after anchor
		foundChar := body[pos]
		if foundChar < '0' || foundChar > '9' {
			continue
		}

		foundIdx := int(foundChar - '0')
		if foundIdx != expectedIdx {
			return true, string(foundChar)
		}
	}
	return false, ""
}

// containsAnchor checks if the response body contains the anchor string.
func containsAnchor(body, anchor string) bool {
	return strings.Contains(body, anchor)
}

// isWafBlocked checks if the response indicates WAF/rate limit blocking.
func isWafBlocked(statusCode int, serverHeader string) bool {
	if statusCode == 429 {
		return true
	}
	if statusCode == 403 {
		if strings.HasPrefix(strings.ToLower(serverHeader), "cloudflare") {
			return true
		}
		if strings.HasPrefix(serverHeader, "AkamaiGHos") {
			return true
		}
		if serverHeader == "CloudFront" {
			return true
		}
	}
	if statusCode == 503 {
		if strings.HasPrefix(strings.ToLower(serverHeader), "cloudflare") {
			return true
		}
	}
	return false
}

// status403To421Filter filters out false positives where status changes from 403 to 421.
// This is a specific Burp FP filter from the original Interference.java.
func status403To421Filter(baselineStatus, responseStatus int) bool {
	return baselineStatus == 403 && responseStatus == 421
}
