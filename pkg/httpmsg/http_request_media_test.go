package httpmsg

import "testing"

func TestHttpRequest_IsMediaPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"html page", "/index.html", false},
		{"api endpoint", "/api/users?id=1", false},
		{"no extension", "/dashboard", false},
		{"javascript asset", "/static/app.js", true},
		{"stylesheet", "/static/site.css", true},
		{"image", "/assets/logo.png", true},
		{"font", "/fonts/icon.woff2", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := ParseRawRequest("GET " + tc.path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
			if err != nil {
				t.Fatalf("ParseRawRequest: %v", err)
			}
			if got := rr.Request().IsMediaPath(); got != tc.want {
				t.Errorf("IsMediaPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
			// Memoized result must be stable across repeated calls.
			if got := rr.Request().IsMediaPath(); got != tc.want {
				t.Errorf("IsMediaPath(%q) second call = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
