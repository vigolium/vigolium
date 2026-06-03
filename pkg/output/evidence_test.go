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
