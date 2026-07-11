package output

import (
	"strings"
	"testing"
)

func TestBuildEvidence(t *testing.T) {
	tests := []struct {
		name           string
		label          string
		request        string
		response       string
		want           string
		wantEmpty      bool
		wantMarkerLine string // first line, when non-empty
	}{
		{
			name:      "both empty returns empty",
			label:     "baseline",
			request:   "",
			response:  "",
			wantEmpty: true,
		},
		{
			name:     "no label is bare req/sep/resp",
			label:    "",
			request:  "GET / HTTP/1.1",
			response: "HTTP/1.1 200 OK",
			want:     "GET / HTTP/1.1" + EvidenceSeparator + "HTTP/1.1 200 OK",
		},
		{
			name:           "label prefixes a marker line",
			label:          "baseline",
			request:        "GET / HTTP/1.1",
			response:       "HTTP/1.1 403 Forbidden",
			wantMarkerLine: "# [baseline]",
			want:           "# [baseline]\nGET / HTTP/1.1" + EvidenceSeparator + "HTTP/1.1 403 Forbidden",
		},
		{
			name:     "request-only still builds",
			label:    "attack",
			request:  "GET /admin HTTP/1.1",
			response: "",
			want:     "# [attack]\nGET /admin HTTP/1.1" + EvidenceSeparator,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildEvidence(tc.label, tc.request, tc.response)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("expected empty, got %q", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("BuildEvidence(%q,%q,%q)\n  got:  %q\n  want: %q", tc.label, tc.request, tc.response, got, tc.want)
			}
			// A labeled entry must be splittable on the separator the same way the
			// storage layer and UI split it.
			if tc.request != "" && tc.response != "" {
				if n := strings.Count(got, EvidenceSeparator); n != 1 {
					t.Fatalf("expected exactly one separator, got %d in %q", n, got)
				}
			}
			if tc.wantMarkerLine != "" {
				if first := got[:strings.IndexByte(got, '\n')]; first != tc.wantMarkerLine {
					t.Fatalf("expected marker line %q, got %q", tc.wantMarkerLine, first)
				}
			}
		})
	}
}

// TestParseEvidenceRoundTrip verifies ParseEvidence is the exact inverse of
// BuildEvidence (Claim B: one shared parser for the evidence format), and that a
// free-form entry with no separator is reported as Prose rather than a bogus pair.
func TestParseEvidenceRoundTrip(t *testing.T) {
	cases := []struct{ label, request, response string }{
		{"", "GET / HTTP/1.1", "HTTP/1.1 200 OK"},
		{"baseline", "GET / HTTP/1.1", "HTTP/1.1 403 Forbidden"},
		{"attack", "GET /admin HTTP/1.1", ""},
		{"confirm round 2", "", "HTTP/1.1 500"},
	}
	for _, tc := range cases {
		built := BuildEvidence(tc.label, tc.request, tc.response)
		p := ParseEvidence(built)
		if !p.IsPair() {
			t.Fatalf("ParseEvidence(%q) reported prose %q, want a pair", built, p.Prose)
		}
		if p.Label != tc.label || p.Request != tc.request || p.Response != tc.response {
			t.Fatalf("round-trip mismatch for (%q,%q,%q): got label=%q request=%q response=%q",
				tc.label, tc.request, tc.response, p.Label, p.Request, p.Response)
		}
	}

	prose := ParseEvidence("just a free-form note, no separator")
	if prose.IsPair() {
		t.Fatalf("expected prose entry, got pair: %+v", prose)
	}
	if prose.Prose != "just a free-form note, no separator" {
		t.Fatalf("prose = %q", prose.Prose)
	}
}
