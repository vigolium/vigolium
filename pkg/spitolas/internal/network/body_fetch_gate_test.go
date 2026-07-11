package network

import "testing"

// TestShouldFetchResponseBody locks in the body-fetch skip gate: HTML/JS/JSON/
// XML/API responses are always fetched (they drive discovery), while binary
// static assets are fetched only when retained and under the size cap. Skipping
// a discarded static body also skips that response's page enumeration + CDP
// body transfer — the dominant per-response cost.
func TestShouldFetchResponseBody(t *testing.T) {
	entry := func(ct, url string) *TrafficEntry {
		return &TrafficEntry{
			ContentType: ct,
			Request:     RequestData{URL: url},
			Response:    &ResponseData{Status: 200},
		}
	}

	cases := []struct {
		name        string
		entry       *TrafficEntry
		includeBody bool
		encodedLen  float64
		want        bool
	}{
		{"html always fetched", entry("text/html", "https://x/index"), false, 0, true},
		{"json always fetched", entry("application/json", "https://x/api/users"), false, 0, true},
		{"javascript always fetched", entry("application/javascript", "https://x/app.js"), false, 0, true},
		{"xml always fetched", entry("text/xml", "https://x/feed"), false, 0, true},
		{"image discarded → skip", entry("image/png", "https://x/logo.png"), false, 0, false},
		{"font discarded → skip", entry("font/woff2", "https://x/f.woff2"), false, 0, false},
		{"static by extension discarded → skip", entry("", "https://x/a.css"), false, 0, false},
		{"image retained + small → fetch", entry("image/png", "https://x/logo.png"), true, 1000, true},
		{"image retained + oversized → skip", entry("image/png", "https://x/huge.png"), true, maxStaticBodyFetchBytes + 1, false},
		{"nil response → skip", &TrafficEntry{Request: RequestData{URL: "https://x/y"}}, true, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFetchResponseBody(tc.entry, tc.includeBody, tc.encodedLen); got != tc.want {
				t.Errorf("shouldFetchResponseBody = %v, want %v", got, tc.want)
			}
		})
	}
}
