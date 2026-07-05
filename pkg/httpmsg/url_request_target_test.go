package httpmsg

import (
	"strings"
	"testing"
)

// TestURLToRequestPreservesEncoding guards Group 3: converting a URL string into
// a request must NOT decode percent-encoding in the path (that would break
// deliberate path-normalization bypasses like /%23/../x).
func TestURLToRequestPreservesEncoding(t *testing.T) {
	cases := []struct {
		in       string
		wantLine string
	}{
		{"https://h.example.com/%23/../metrics", "GET /%23/../metrics HTTP/1.1"},
		{"https://h.example.com/..;/admin", "GET /..;/admin HTTP/1.1"},
		{"https://h.example.com/foo%2ebar", "GET /foo%2ebar HTTP/1.1"},
		{"https://h.example.com//app//x", "GET //app//x HTTP/1.1"},
		{"https://h.example.com/search?q=a%20b", "GET /search?q=a%20b HTTP/1.1"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			// GetRawRequestFromURL (primary converter: scan-url, discovery→scan, imports).
			rr, err := GetRawRequestFromURL(tc.in)
			if err != nil {
				t.Fatalf("GetRawRequestFromURL(%q): %v", tc.in, err)
			}
			line := requestLine(rr.Request().Raw())
			if line != tc.wantLine {
				t.Errorf("GetRawRequestFromURL(%q) request-line = %q, want %q", tc.in, line, tc.wantLine)
			}

			// HttpRequestFromURL (browser-header variant).
			req, err := HttpRequestFromURL(tc.in)
			if err != nil {
				t.Fatalf("HttpRequestFromURL(%q): %v", tc.in, err)
			}
			line2 := requestLine(req.Raw())
			if line2 != tc.wantLine {
				t.Errorf("HttpRequestFromURL(%q) request-line = %q, want %q", tc.in, line2, tc.wantLine)
			}
		})
	}
}

func requestLine(raw []byte) string {
	s := string(raw)
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
