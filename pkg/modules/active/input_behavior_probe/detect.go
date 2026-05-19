package input_behavior_probe

import (
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// detectionBaseline holds the reference values for comparison.
type detectionBaseline struct {
	tags       string
	statusCode int
	bodyLen    int
}

// newDetectionBaseline creates a baseline from a cached baseline entry.
func newDetectionBaseline(entry *modkit.BaselineEntry) *detectionBaseline {
	return &detectionBaseline{
		tags:       ExtractTags(entry.Response.BodyToString()),
		statusCode: entry.StatusCode,
		bodyLen:    entry.BodyLen,
	}
}

// behaviorChange describes what changed between baseline and fuzzed response.
type behaviorChange struct {
	TagsChanged       bool
	StatusCodeChanged bool
	BaseTags          string
	FuzzTags          string
	BaseStatus        int
	FuzzStatus        int
	IsInteresting     bool
}

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// detectChange compares a fuzzed response against the baseline.
// A change is interesting when HTML tag structure differs or a notable status
// code transition occurs (e.g. 200→500, 403→200, any→500).
func detectChange(baseline *detectionBaseline, fuzzBody string, fuzzStatus int) *behaviorChange {
	fuzzTags := ExtractTags(fuzzBody)
	tagsChanged := baseline.tags != fuzzTags

	statusChanged := baseline.statusCode != fuzzStatus

	// Suppress findings when the probe is blocked by an auth/WAF/rate-limit layer
	// but the baseline wasn't. The tag/status delta is the WAF's block page, not
	// application input handling. The reverse (denied→allowed, e.g. 403→200) is
	// still flagged below as a genuine bypass.
	if isAccessDenied(fuzzStatus) && !isAccessDenied(baseline.statusCode) {
		return &behaviorChange{
			TagsChanged:       tagsChanged,
			StatusCodeChanged: statusChanged,
			BaseTags:          baseline.tags,
			FuzzTags:          fuzzTags,
			BaseStatus:        baseline.statusCode,
			FuzzStatus:        fuzzStatus,
			IsInteresting:     false,
		}
	}

	interesting := tagsChanged

	// Notable status transitions
	if statusChanged {
		switch {
		case baseline.statusCode == 200 && fuzzStatus >= 500:
			interesting = true
		case baseline.statusCode == 403 && fuzzStatus == 200:
			interesting = true
		case fuzzStatus >= 500:
			interesting = true
		}
	}

	return &behaviorChange{
		TagsChanged:       tagsChanged,
		StatusCodeChanged: statusChanged,
		BaseTags:          baseline.tags,
		FuzzTags:          fuzzTags,
		BaseStatus:        baseline.statusCode,
		FuzzStatus:        fuzzStatus,
		IsInteresting:     interesting,
	}
}

// buildProbeResult constructs a ResultEvent for a detected behavior change.
func buildProbeResult(
	urlStr string,
	raw []byte,
	resp string,
	param, probeType, payload string,
	change *behaviorChange,
) *output.ResultEvent {
	return &output.ResultEvent{
		URL:              urlStr,
		Request:          string(raw),
		Response:         resp,
		FuzzingParameter: param,
		ExtractedResults: []string{payload},
		Metadata: map[string]any{
			"probe_type":  probeType,
			"base_tags":   change.BaseTags,
			"fuzz_tags":   change.FuzzTags,
			"base_status": change.BaseStatus,
			"fuzz_status": change.FuzzStatus,
		},
	}
}
