package backslash_transformation

import (
	"html"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Classification represents how a transformation is categorized.
type Classification int

const (
	ClassificationBoring            Classification = iota // Payload unchanged or URL-encoded
	ClassificationBackslashConsumed                       // Backslash stripped from \char
	ClassificationInteresting                             // Escape decoded or unexpected transform
	ClassificationTruncated                               // Reflection was truncated
	ClassificationDisappeared                             // Reflection disappeared entirely
)

func (c Classification) String() string {
	switch c {
	case ClassificationBoring:
		return "boring"
	case ClassificationBackslashConsumed:
		return "backslashConsumed"
	case ClassificationInteresting:
		return "interesting"
	case ClassificationTruncated:
		return "truncated"
	case ClassificationDisappeared:
		return "disappeared"
	default:
		return "unknown"
	}
}

// TransformResult represents a single transformation observation.
type TransformResult struct {
	Probe          string         // Original probe (e.g., "\\x41")
	Received       string         // What we received back
	Classification Classification // How we classified it
	Pretty         string         // Formatted: "probe => received"
}

// ExtractBetweenAnchors finds reflected content between left and right anchors.
// It searches for leftAnchor, then extracts up to 20 bytes and looks for rightAnchor.
// Returns all unique transformation results found.
func ExtractBetweenAnchors(body []byte, leftAnchor, rightAnchor string) []string {
	results := make(map[string]struct{})

	leftMatches := httpmsg.GetMatches(body, []byte(leftAnchor), -1)
	if len(leftMatches) == 0 {
		return []string{"Reflection disappeared"}
	}

	for _, match := range leftMatches {
		startPos := match[1] // End of leftAnchor match = start of content

		// Extract up to 20 bytes after leftAnchor
		endPos := min(startPos+20, len(body))

		content := body[startPos:endPos]

		// Find rightAnchor within extracted content
		rightMatches := httpmsg.GetMatches(content, []byte(rightAnchor), 1)
		if len(rightMatches) == 0 {
			results["Truncated"] = struct{}{}
			continue
		}

		// Extract content between anchors
		reflectionEnd := rightMatches[0][0]
		reflected := content[:reflectionEnd]

		// Unescape HTML entities (like Burp's StringEscapeUtils.unescapeHtml4)
		unescaped := html.UnescapeString(string(reflected))
		results[unescaped] = struct{}{}
	}

	// Convert map to slice
	var resultSlice []string
	for r := range results {
		resultSlice = append(resultSlice, r)
	}
	return resultSlice
}

// ClassifyTransformation determines if a transformation is interesting.
//   - If probe starts with backslash:
//   - boring: received == probe OR URLDecode(received) == probe
//   - backslashConsumed: received == probe[1:] (backslash stripped)
//   - interesting: any other transformation
//   - If probe doesn't start with backslash:
//   - boring: received == probe OR URLDecode(received) == probe
//   - interesting: any other transformation
func ClassifyTransformation(probe, received string, expectBackslashConsumption bool) *TransformResult {
	pretty := probe + " => " + received

	result := &TransformResult{
		Probe:    probe,
		Received: received,
		Pretty:   pretty,
	}

	// Handle special cases
	if received == "Truncated" {
		result.Classification = ClassificationTruncated
		return result
	}
	if received == "Reflection disappeared" {
		result.Classification = ClassificationDisappeared
		return result
	}

	startsWithBackslash := strings.HasPrefix(probe, "\\")

	// Try URL decode the received value
	urlDecoded, err := url.QueryUnescape(received)
	if err != nil {
		urlDecoded = received
	}

	if startsWithBackslash {
		// For backslash-prefixed probes (escape sequences)
		if received == probe || urlDecoded == probe {
			// No transformation or just URL encoding
			if expectBackslashConsumption {
				// If we expect backslash consumption but didn't see it, that's interesting
				result.Classification = ClassificationInteresting
			} else {
				result.Classification = ClassificationBoring
			}
			return result
		}

		// Check if backslash was consumed (received == probe without leading backslash)
		if len(probe) > 1 && received == probe[1:] {
			if expectBackslashConsumption {
				result.Classification = ClassificationBoring
			} else {
				result.Classification = ClassificationBackslashConsumed
			}
			return result
		}

		// Any other transformation is interesting
		result.Classification = ClassificationInteresting
		return result
	}

	// For non-backslash probes (special characters)
	if received == probe || urlDecoded == probe {
		result.Classification = ClassificationBoring
		return result
	}

	// Any transformation is interesting
	result.Classification = ClassificationInteresting
	return result
}

// IsBackslashConsumed checks if "zz" appears in the transformation results without backslash.
// This is used to determine if the server consumes/strips backslashes.
func IsBackslashConsumed(transformations []string) bool {
	return slices.Contains(transformations, "zz")
}

// FilterInteresting filters transformation results to only interesting ones.
func FilterInteresting(results []*TransformResult) []*TransformResult {
	var interesting []*TransformResult
	for _, r := range results {
		if r.Classification == ClassificationInteresting ||
			r.Classification == ClassificationBackslashConsumed {
			interesting = append(interesting, r)
		}
	}
	return interesting
}
