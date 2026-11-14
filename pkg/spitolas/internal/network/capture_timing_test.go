package network

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestFinalizeTimings: DurationMs is request → response headers; the CDP body
// fetch afterwards is reported separately instead of inflating the latency.
func TestFinalizeTimings(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	p := &pendingEntry{entry: &TrafficEntry{}, startTime: start, responseAt: start.Add(120 * time.Millisecond)}
	finalizeTimings(p, 1500*time.Millisecond)
	if p.entry.DurationMs != 120 {
		t.Errorf("DurationMs = %d, want 120 (request → response headers)", p.entry.DurationMs)
	}
	if p.entry.BodyFetchMs != 1500 {
		t.Errorf("BodyFetchMs = %d, want 1500", p.entry.BodyFetchMs)
	}

	// No body fetch: nothing reported for it.
	p = &pendingEntry{entry: &TrafficEntry{}, startTime: start, responseAt: start.Add(40 * time.Millisecond)}
	finalizeTimings(p, 0)
	if p.entry.DurationMs != 40 || p.entry.BodyFetchMs != 0 {
		t.Errorf("timings = %d/%d, want 40/0", p.entry.DurationMs, p.entry.BodyFetchMs)
	}

	// No response event seen: elapsed time minus the body fetch.
	p = &pendingEntry{entry: &TrafficEntry{}, startTime: time.Now().Add(-1 * time.Second)}
	finalizeTimings(p, 400*time.Millisecond)
	if d := p.entry.DurationMs; d < 550 || d > 900 {
		t.Errorf("fallback DurationMs = %d, want ≈600 (elapsed minus the body fetch)", d)
	}

	// Never measured stays 0.
	p = &pendingEntry{entry: &TrafficEntry{}}
	finalizeTimings(p, 0)
	if p.entry.DurationMs != 0 {
		t.Errorf("unmeasured DurationMs = %d, want 0", p.entry.DurationMs)
	}
}

// TestResponseTimeRecordedOnResponse guards the other half: the response
// arrival time must be stamped in onResponseReceived, and onLoadingFinished
// must time the body fetch and hand both to finalizeTimings rather than
// measuring after the fetch.
func TestResponseTimeRecordedOnResponse(t *testing.T) {
	src, err := os.ReadFile("capture.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	fn := func(name string) string {
		i := strings.Index(body, "func (c *Capture) "+name+"(")
		if i == -1 {
			t.Fatalf("%s not found; update this guard", name)
		}
		rest := body[i:]
		if end := strings.Index(rest, "\nfunc "); end != -1 {
			rest = rest[:end]
		}
		return rest
	}
	if !strings.Contains(fn("onResponseReceived"), "pending.responseAt = time.Now()") {
		t.Error("onResponseReceived must stamp pending.responseAt")
	}
	// The body fetch moved to the worker pool (MISS-29b): onLoadingFinished
	// hands off, runBodyJob times the fetch, finishResponse finalises.
	finished := fn("onLoadingFinished")
	if !strings.Contains(fn("finishResponse"), "finalizeTimings(pending, bodyFetch)") {
		t.Error("finishResponse must set timings through finalizeTimings")
	}
	if !strings.Contains(fn("runBodyJob"), "bodyFetch := time.Since(fetchStart)") {
		t.Error("runBodyJob must time the body fetch")
	}
	if strings.Contains(finished, "DurationMs = elapsedMs(") {
		t.Error("onLoadingFinished must not measure DurationMs after the body fetch")
	}
}
