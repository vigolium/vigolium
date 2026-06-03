package discovery

import (
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
)

func newTestJSExtractedTask(reqs []jsscan.ExtractedRequest) *JSExtractedRequestTask {
	dir, _ := url.Parse("https://example.com/app/")
	return NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL:               dir,
		Depth:                1,
		GetExtractedRequests: func() []jsscan.ExtractedRequest { return reqs },
	})
}

func TestIsReplayableMethod(t *testing.T) {
	cases := map[string]bool{
		"GET":  true,
		"POST": true,
		"PUT":  true,
		"ws":   false,
		"WS":   false,
		"sse":  false,
		"SSE":  false,
	}
	for method, want := range cases {
		if got := isReplayableMethod(method); got != want {
			t.Errorf("isReplayableMethod(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestGenerateAllVariantsSkipsNonReplayableMethods(t *testing.T) {
	reqs := []jsscan.ExtractedRequest{
		{URL: "wss://example.com/ws/notifications", Method: "WS"},
		{URL: "/events/stream", Method: "SSE"},
		// Absolute different-host URL is returned as-is by resolveRequestURL,
		// guaranteeing a deterministic positive variant.
		{URL: "https://api.other.com/v1/ping", Method: "GET"},
	}

	task := newTestJSExtractedTask(reqs)
	variants := task.GenerateAllVariants()

	for _, v := range variants {
		if v.Method == "WS" || v.Method == "SSE" {
			t.Fatalf("non-replayable method %q produced a variant: %+v", v.Method, v)
		}
		if strings.Contains(v.URL, "/ws/notifications") || strings.Contains(v.URL, "/events/stream") {
			t.Fatalf("non-replayable URL was replayed: %s", v.URL)
		}
	}

	foundPing := false
	for _, v := range variants {
		if strings.Contains(v.URL, "api.other.com/v1/ping") {
			foundPing = true
		}
	}
	if !foundPing {
		t.Fatalf("expected replayable GET to produce a variant, got %+v", variants)
	}
}
