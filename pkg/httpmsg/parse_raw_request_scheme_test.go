package httpmsg

import "testing"

// TestParseRawRequestSchemeInference locks in how ParseRawRequest resolves the
// scheme for origin-form request lines (no scheme on the request line): explicit
// request-line scheme > well-known Host port > same-origin Origin/Referer header
// > https default.
func TestParseRawRequestSchemeInference(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantURL  string
		wantPort int
	}{
		{
			// The reported bug: an http service on a non-standard port whose only
			// scheme signal is a same-origin Referer must not be upgraded to https.
			name:     "referer pins http on non-standard port",
			raw:      "GET /rest/products/search?q=a HTTP/1.1\r\nHost: localhost:3000\r\nReferer: http://localhost:3000/\r\n\r\n",
			wantURL:  "http://localhost:3000/rest/products/search?q=a",
			wantPort: 3000,
		},
		{
			name:     "origin pins http on non-standard port",
			raw:      "GET /api HTTP/1.1\r\nHost: localhost:3000\r\nOrigin: http://localhost:3000\r\n\r\n",
			wantURL:  "http://localhost:3000/api",
			wantPort: 3000,
		},
		{
			// No Origin/Referer signal → keep the https default (unchanged behavior).
			name:     "no origin or referer keeps https default",
			raw:      "GET /api HTTP/1.1\r\nHost: localhost:3000\r\n\r\n",
			wantURL:  "https://localhost:3000/api",
			wantPort: 3000,
		},
		{
			// A Referer to a different host (CORS / external referrer) must be
			// ignored so it can't mislead the scheme.
			name:     "cross-origin referer ignored keeps https default",
			raw:      "GET /api HTTP/1.1\r\nHost: localhost:3000\r\nReferer: http://evil.example/\r\n\r\n",
			wantURL:  "https://localhost:3000/api",
			wantPort: 3000,
		},
		{
			name:     "origin preferred over conflicting referer",
			raw:      "GET /api HTTP/1.1\r\nHost: localhost:3000\r\nReferer: https://localhost:3000/\r\nOrigin: http://localhost:3000\r\n\r\n",
			wantURL:  "http://localhost:3000/api",
			wantPort: 3000,
		},
		{
			name:     "well-known port 80 stays http regardless of referer",
			raw:      "GET /x HTTP/1.1\r\nHost: acme.example:80\r\n\r\n",
			wantURL:  "http://acme.example/x",
			wantPort: 80,
		},
		{
			name:     "well-known port 443 stays https",
			raw:      "GET /x HTTP/1.1\r\nHost: acme.example:443\r\n\r\n",
			wantURL:  "https://acme.example/x",
			wantPort: 443,
		},
		{
			// Non-loopback host, https Referer, non-standard port → https (and the
			// http-service-on-non-standard-port improvement also helps remote hosts).
			name:     "https referer pins https on non-standard port",
			raw:      "GET /x HTTP/1.1\r\nHost: acme.example:8443\r\nReferer: https://acme.example:8443/\r\n\r\n",
			wantURL:  "https://acme.example:8443/x",
			wantPort: 8443,
		},
		{
			// No port on Host + http Referer → default port must follow the scheme.
			name:     "http referer with no host port defaults to port 80",
			raw:      "GET /x HTTP/1.1\r\nHost: acme.example\r\nReferer: http://acme.example/\r\n\r\n",
			wantURL:  "http://acme.example/x",
			wantPort: 80,
		},
		{
			name:     "no signal at all keeps https default",
			raw:      "GET /x HTTP/1.1\r\nHost: acme.example\r\n\r\n",
			wantURL:  "https://acme.example/x",
			wantPort: 443,
		},
		{
			// Opaque origin ("null") must not crash and must not change the default.
			name:     "opaque null origin keeps https default",
			raw:      "POST /x HTTP/1.1\r\nHost: localhost:3000\r\nOrigin: null\r\n\r\n",
			wantURL:  "https://localhost:3000/x",
			wantPort: 3000,
		},
		{
			// Same host but a DIFFERENT port (a :3000 frontend Origin on a request to
			// an :8443 API): the cross-port Origin must be ignored so an HTTPS service
			// on 8443 is not downgraded to http.
			name:     "cross-port origin ignored keeps https default",
			raw:      "GET /x HTTP/1.1\r\nHost: api.example:8443\r\nOrigin: http://api.example:3000\r\n\r\n",
			wantURL:  "https://api.example:8443/x",
			wantPort: 8443,
		},
		{
			name:     "cross-port referer ignored keeps https default",
			raw:      "GET /x HTTP/1.1\r\nHost: api.example:8443\r\nReferer: http://api.example:3000/\r\n\r\n",
			wantURL:  "https://api.example:8443/x",
			wantPort: 8443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := ParseRawRequest(tt.raw)
			if err != nil {
				t.Fatalf("ParseRawRequest: %v", err)
			}
			if got := rr.Target(); got != tt.wantURL {
				t.Errorf("Target() = %q, want %q", got, tt.wantURL)
			}
			if svc := rr.Service(); svc == nil {
				t.Fatal("Service() is nil")
			} else if svc.Port() != tt.wantPort {
				t.Errorf("Service().Port() = %d, want %d", svc.Port(), tt.wantPort)
			}
		})
	}
}
