package authzutil

import (
	"bytes"
	"math"
	"strings"
)

// AuthzVerdict indicates whether authorization was enforced, bypassed, or uncertain.
type AuthzVerdict int

const (
	VerdictEnforced  AuthzVerdict = iota // Access was denied
	VerdictBypassed                      // Access was granted (potential vulnerability)
	VerdictUncertain                     // Could not determine
)

// String returns a human-readable label for an AuthzVerdict.
func (v AuthzVerdict) String() string {
	switch v {
	case VerdictEnforced:
		return "enforced"
	case VerdictBypassed:
		return "bypassed"
	default:
		return "uncertain"
	}
}

// ResponseSummary captures the key attributes of an HTTP response for comparison.
type ResponseSummary struct {
	StatusCode      int
	BodyLength      int
	ContentType     string
	Body            []byte
	HasErrorMessage bool
}

// ResponseComparison holds the result of comparing two HTTP responses.
type ResponseComparison struct {
	StatusCodeMatch      bool
	BodyLengthDelta      int
	BodyLengthRatio      float64
	ContentIdentical     bool
	StructurallyIdentical bool
	UserFieldsDiffer     bool
	DifferingFields      []string
	SharedFields         []string
}

// CompareOptions configures response comparison behavior.
type CompareOptions struct {
	SimilarityThreshold float64
	UserSpecificFields  []string
}

// DefaultCompareOptions returns sensible defaults for response comparison.
func DefaultCompareOptions() CompareOptions {
	return CompareOptions{
		SimilarityThreshold: 0.8,
		UserSpecificFields: []string{
			"username", "user_name", "email", "name", "display_name",
			"first_name", "last_name", "avatar", "profile_url",
		},
	}
}

// SummarizeResponse creates a ResponseSummary from raw response attributes.
func SummarizeResponse(statusCode int, contentType string, body []byte) *ResponseSummary {
	hasError := false
	if len(body) > 0 {
		hasError = ContainsEnforcementString(string(body))
	}
	return &ResponseSummary{
		StatusCode:      statusCode,
		BodyLength:      len(body),
		ContentType:     contentType,
		Body:            body,
		HasErrorMessage: hasError,
	}
}

// CompareResponses compares a baseline response against a probe response.
func CompareResponses(baseline, probe *ResponseSummary, opts CompareOptions) *ResponseComparison {
	if baseline == nil || probe == nil {
		return &ResponseComparison{}
	}

	comp := &ResponseComparison{
		StatusCodeMatch:  baseline.StatusCode == probe.StatusCode,
		ContentIdentical: bytes.Equal(baseline.Body, probe.Body),
	}

	// Body length delta and ratio
	comp.BodyLengthDelta = probe.BodyLength - baseline.BodyLength
	if baseline.BodyLength > 0 {
		smaller := math.Min(float64(baseline.BodyLength), float64(probe.BodyLength))
		larger := math.Max(float64(baseline.BodyLength), float64(probe.BodyLength))
		comp.BodyLengthRatio = smaller / larger
	} else if probe.BodyLength == 0 {
		comp.BodyLengthRatio = 1.0
	}

	// Structural identity: same status + content within similarity threshold
	comp.StructurallyIdentical = comp.StatusCodeMatch && comp.BodyLengthRatio >= opts.SimilarityThreshold

	// Check for user-specific field differences in body text (simple substring check).
	// Full JSON field diffing is deferred to Layer 2.
	if !comp.ContentIdentical && len(opts.UserSpecificFields) > 0 {
		baselineStr := strings.ToLower(string(baseline.Body))
		probeStr := strings.ToLower(string(probe.Body))
		for _, field := range opts.UserSpecificFields {
			inBaseline := strings.Contains(baselineStr, field)
			inProbe := strings.Contains(probeStr, field)
			if inBaseline && inProbe {
				comp.SharedFields = append(comp.SharedFields, field)
			}
			if inBaseline != inProbe {
				comp.DifferingFields = append(comp.DifferingFields, field)
				comp.UserFieldsDiffer = true
			}
		}
	}

	return comp
}
