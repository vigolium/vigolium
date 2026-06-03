package input_behavior_probe

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// tagChangeMargin is how many added/removed opening tags a probe must show BEYOND
// the page's calibrated natural jitter before its body structure is treated as
// changed. Small enough to catch a real structural break, large enough to ignore
// incidental flicker the jitter sample didn't happen to capture.
const tagChangeMargin = 2

// detectionBaseline holds the reference values for comparison.
type detectionBaseline struct {
	tags       string         // readable opening-tag string, for reporting
	tagCounts  map[string]int // order-independent tag multiset, for distance
	statusCode int
	tagJitter  int // calibrated natural per-request tag variance (added/removed tags)
}

// newDetectionBaseline creates a baseline from a cached baseline entry.
func newDetectionBaseline(entry *modkit.BaselineEntry) *detectionBaseline {
	tags, counts := scanTags(entry.Response.BodyToString())
	return &detectionBaseline{
		tags:       tags,
		tagCounts:  counts,
		statusCode: entry.StatusCode,
	}
}

// calibrateTagJitter measures the page's natural per-request tag variance by
// re-fetching the unmodified request a couple of times and recording the largest
// tag-distance from the baseline. Dynamic content (rotating ads, CDN-injected
// challenge scripts, A/B widgets) AND a stale cached baseline (up to 5 min old)
// both surface here, so detectChange can demand a probe diverge by MORE than this
// before treating it as input-driven behavior rather than ambient page noise.
func calibrateTagJitter(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, baseline *detectionBaseline) {
	const controlSamples = 2
	raw := ctx.Request().Raw()
	for range controlSamples {
		counts, ok := fetchTagCounts(ctx, httpClient, raw)
		if !ok {
			continue
		}
		if d := tagDistance(baseline.tagCounts, counts); d > baseline.tagJitter {
			baseline.tagJitter = d
		}
	}
}

// fetchTagCounts re-issues raw and returns its response body's tag multiset. ok is
// false on any parse/transport error or nil response. NoClustering bypasses the
// requester's 500ms response cache so each sample is a genuinely fresh render —
// a cached replay would report zero variance and defeat the calibration.
func fetchTagCounts(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (map[string]int, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return nil, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return nil, false
	}
	return extractTagCounts(resp.Body().String()), true
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
	statusInteresting bool // interest came from a notable status transition (not tags)
}

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// detectChange compares a fuzzed response against the baseline. A change is
// interesting when the body's HTML tag structure diverges from the baseline by
// MORE than the page's natural jitter (calibrated separately), or a notable
// status transition occurs (e.g. 200→500, 403→200, any→500). The tag comparison
// is order-independent and jitter-tolerant: exact string equality flagged any
// rotating ad, CDN challenge script, or stale-baseline drift as a behavior change.
func detectChange(baseline *detectionBaseline, fuzzBody string, fuzzStatus int) *behaviorChange {
	fuzzTags, fuzzCounts := scanTags(fuzzBody)
	tagsChanged := tagDistance(baseline.tagCounts, fuzzCounts) > baseline.tagJitter+tagChangeMargin

	statusChanged := baseline.statusCode != fuzzStatus

	change := &behaviorChange{
		TagsChanged:       tagsChanged,
		StatusCodeChanged: statusChanged,
		BaseTags:          baseline.tags,
		FuzzTags:          fuzzTags,
		BaseStatus:        baseline.statusCode,
		FuzzStatus:        fuzzStatus,
	}

	// Suppress findings when the probe is blocked by an auth/WAF/rate-limit layer
	// but the baseline wasn't. The tag/status delta is the WAF's block page, not
	// application input handling. The reverse (denied→allowed, e.g. 403→200) is
	// still flagged below as a genuine bypass.
	if isAccessDenied(fuzzStatus) && !isAccessDenied(baseline.statusCode) {
		return change
	}

	// Notable status transitions are an independent signal from the tag structure.
	if statusChanged {
		switch {
		case baseline.statusCode == 200 && fuzzStatus >= 500:
			change.statusInteresting = true
		case baseline.statusCode == 403 && fuzzStatus == 200:
			change.statusInteresting = true
		case fuzzStatus >= 500:
			change.statusInteresting = true
		}
	}

	change.IsInteresting = tagsChanged || change.statusInteresting
	return change
}

// confirmChange decides whether an interesting change is worth reporting. A
// notable status transition stands on its own. A tag-structure change, however,
// must REPRODUCE on a fresh re-fetch of the same probe and still exceed the page's
// natural jitter — so a one-off render difference (the reported "response is not
// much different" case, dominated by rotating headers/dynamic body fragments) is
// dropped rather than reported. Fails closed: an unconfirmable tag change is not
// reported.
func confirmChange(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
	probeRaw []byte,
	change *behaviorChange,
) bool {
	if change == nil || !change.IsInteresting {
		return false
	}
	if change.statusInteresting {
		return true
	}
	counts, ok := fetchTagCounts(ctx, httpClient, probeRaw)
	if !ok {
		return false
	}
	return tagDistance(baseline.tagCounts, counts) > baseline.tagJitter+tagChangeMargin
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
