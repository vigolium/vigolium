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

// minComparableTags is the fewest opening HTML tags a fuzzed response body must
// contain before its structure is compared to the baseline. An empty stub, a bare
// redirect notice, or a non-HTML payload (an XML error, a JSON body) falls below
// this — comparing it to an HTML baseline only measures "this isn't the page" and
// registers a maximal, bogus tag distance, the reported 404/302 empty-body false
// positive.
const minComparableTags = 3

// isContentResponse reports whether status serves application content a tag
// comparison can be drawn against — a 2xx body. Redirects (3xx) and client errors
// (4xx) hand back a DIFFERENT resource (a login redirect, a not-found stub), so
// their body's tag structure is not comparable to the baseline page's; any delta
// is a page-TYPE change, which the status leg judges separately.
func isContentResponse(status int) bool {
	return status >= 200 && status < 300
}

// totalTags is the number of opening HTML tags in a multiset (nil-safe).
func totalTags(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

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

// fetchProbeOutcome re-issues raw and returns its response status code and body's
// tag multiset. ok is false on any parse/transport error or nil response.
// NoClustering bypasses the requester's 500ms response cache so each sample is a
// genuinely fresh render — a cached replay would report zero variance and defeat
// both jitter calibration and the confirm re-fetch.
func fetchProbeOutcome(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (int, map[string]int, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, nil, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return 0, nil, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, nil, false
	}
	return resp.Response().StatusCode, extractTagCounts(resp.Body().String()), true
}

// fetchTagCounts re-issues raw and returns its response body's tag multiset,
// discarding the status — used by jitter calibration, which only measures body
// variance. ok is false on any parse/transport error or nil response.
func fetchTagCounts(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (map[string]int, bool) {
	_, counts, ok := fetchProbeOutcome(ctx, httpClient, raw)
	return counts, ok
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

// isCDNOriginError reports whether status is a CDN/edge→origin connectivity error
// (Cloudflare's 520–530 family). These are infrastructure blips — the edge could
// not get a clean answer from origin — never an application parser/injection error,
// so a probe that happens to hit one mid-run must not be read as a behavior change.
func isCDNOriginError(status int) bool {
	return status >= 520 && status <= 530
}

// notableStatusTransition reports whether a baseline→fuzz status pair is a
// security-relevant transition worth surfacing on its own: a server/parser error
// appearing (→5xx, excluding CDN origin blips), or an access-control flip
// (403→200). Ordinary cross-class moves (200→404, 200→302, 403→404) are NOT
// notable — they mean the probe reached a DIFFERENT resource, which is expected for
// a path/param probe and is not, by itself, an input-handling signal.
func notableStatusTransition(base, fuzz int) bool {
	if base == fuzz {
		return false
	}
	switch {
	case base == 403 && fuzz == 200:
		return true
	case fuzz >= 500 && !isCDNOriginError(fuzz):
		return true
	default:
		return false
	}
}

// detectChange compares a fuzzed response against the baseline. A change is
// interesting when the body's HTML tag structure diverges from the baseline by
// MORE than the page's natural jitter (calibrated separately), or a notable
// status transition occurs (e.g. 200→500, 403→200, any→500). The tag comparison
// is order-independent and jitter-tolerant: exact string equality flagged any
// rotating ad, CDN challenge script, or stale-baseline drift as a behavior change.
func detectChange(baseline *detectionBaseline, fuzzBody string, fuzzStatus int) *behaviorChange {
	fuzzTags, fuzzCounts := scanTags(fuzzBody)

	// A tag-structure delta is only a meaningful input-handling signal when the
	// fuzzed response is structurally comparable to the baseline: both must serve
	// 2xx content (a 3xx redirect or 4xx error returns a DIFFERENT resource, so the
	// delta measures the page TYPE changing — expected for a path probe that 404s,
	// and the genuinely-notable cross-class transitions are flagged by the status
	// leg below), and the fuzz body must carry real HTML structure (an empty or
	// near-empty body has ~zero tags and registers a maximal, bogus distance against
	// any HTML baseline — the reported 404/302 empty-body false positives).
	structurallyComparable := isContentResponse(baseline.statusCode) &&
		isContentResponse(fuzzStatus) &&
		totalTags(fuzzCounts) >= minComparableTags
	tagsChanged := structurallyComparable &&
		tagDistance(baseline.tagCounts, fuzzCounts) > baseline.tagJitter+tagChangeMargin

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

	// A notable status transition is an independent signal from the tag structure.
	// confirmChange re-verifies it against a fresh probe AND a no-payload control
	// before it is reported, so a one-off blip or a flapping baseline never survives.
	change.statusInteresting = notableStatusTransition(baseline.statusCode, fuzzStatus)

	change.IsInteresting = tagsChanged || change.statusInteresting
	return change
}

// confirmChange decides whether an interesting change is worth reporting. BOTH the
// status leg and the tag leg must survive a fresh re-check: a divergence that does
// not reproduce, or that the no-payload control reproduces just as well, is ambient
// noise ("the response is the same with or without the payload") rather than
// input-driven behavior. Fails closed: an unconfirmable change is not reported.
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
		return confirmStatusTransition(ctx, httpClient, baseline, probeRaw)
	}
	counts, ok := fetchTagCounts(ctx, httpClient, probeRaw)
	if !ok {
		return false
	}
	// The reproduction must itself carry real HTML structure — an empty or
	// near-empty re-fetch (a flaky redirect/error) would otherwise register a bogus
	// maximal distance and "confirm" the very empty-body FP detectChange suppresses.
	if totalTags(counts) < minComparableTags {
		return false
	}
	return tagDistance(baseline.tagCounts, counts) > baseline.tagJitter+tagChangeMargin
}

// confirmStatusTransition validates that a notable status transition is genuinely
// payload-driven and stable rather than a one-off CDN/origin blip or a page that
// flaps between statuses on its own. It requires BOTH:
//
//	(1) the probe to REPRODUCE the same notable transition on a fresh re-fetch, and
//	(2) the unmodified CONTROL to still serve the baseline status — proving the
//	    probe, not ambient flapping, caused the divergence.
//
// A transient 5xx fails (1); a baseline that was itself a cold-start/transient
// status (so the page now answers the no-payload control the same way the probe
// does) fails (2). Fails closed on any transport error.
func confirmStatusTransition(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
	probeRaw []byte,
) bool {
	probeStatus, _, ok := fetchProbeOutcome(ctx, httpClient, probeRaw)
	if !ok || !notableStatusTransition(baseline.statusCode, probeStatus) {
		return false
	}
	ctrlStatus, _, ok := fetchProbeOutcome(ctx, httpClient, ctx.Request().Raw())
	if !ok {
		return false
	}
	return ctrlStatus == baseline.statusCode
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
