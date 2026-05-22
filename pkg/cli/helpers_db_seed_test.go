package cli

import (
	"strings"
	"testing"
)

func TestHasAuthHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    bool
	}{
		{"authorization", map[string][]string{"Authorization": {"Bearer x"}}, true},
		{"cookie lowercase", map[string][]string{"cookie": {"a=b"}}, true},
		{"x-api-key mixed case", map[string][]string{"X-Api-Key": {"k"}}, true},
		{"no auth", map[string][]string{"Content-Type": {"application/json"}}, false},
		{"empty", map[string][]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAuthHeader(tt.headers); got != tt.want {
				t.Errorf("hasAuthHeader(%v) = %v, want %v", tt.headers, got, tt.want)
			}
		})
	}
}

func TestBuildRawRequest(t *testing.T) {
	t.Run("default port omits port in Host", func(t *testing.T) {
		raw := string(buildRawRequest("GET", "/api", "example.com", 443, "https", nil, nil))
		if !strings.HasPrefix(raw, "GET /api HTTP/1.1\r\n") {
			t.Errorf("bad request line: %q", raw)
		}
		if !strings.Contains(raw, "Host: example.com\r\n") {
			t.Errorf("expected port-less Host: %q", raw)
		}
		if !strings.HasSuffix(raw, "\r\n\r\n") {
			t.Errorf("expected blank-line terminator with no body: %q", raw)
		}
	})

	t.Run("non-default port included in Host", func(t *testing.T) {
		raw := string(buildRawRequest("GET", "/", "example.com", 8443, "https", nil, nil))
		if !strings.Contains(raw, "Host: example.com:8443\r\n") {
			t.Errorf("expected port in Host: %q", raw)
		}
	})

	t.Run("caller Host header is not duplicated", func(t *testing.T) {
		hdrs := map[string][]string{"Host": {"ignored.example"}, "X-Test": {"1"}}
		raw := string(buildRawRequest("POST", "/x", "real.example", 80, "http", hdrs, []byte("body")))
		if strings.Count(raw, "Host:") != 1 {
			t.Errorf("Host header must appear exactly once: %q", raw)
		}
		if !strings.Contains(raw, "Host: real.example\r\n") {
			t.Errorf("expected derived Host, not caller's: %q", raw)
		}
		if !strings.HasSuffix(raw, "\r\n\r\nbody") {
			t.Errorf("expected body appended after blank line: %q", raw)
		}
		if !strings.Contains(raw, "X-Test: 1\r\n") {
			t.Errorf("expected extra header preserved: %q", raw)
		}
	})
}

func TestBuildRawResponse(t *testing.T) {
	t.Run("zero status yields nil", func(t *testing.T) {
		if buildRawResponse(0, "", nil, "", nil) != nil {
			t.Error("status 0 must yield nil response")
		}
	})

	t.Run("sets content-length when body present", func(t *testing.T) {
		raw := string(buildRawResponse(200, "OK", nil, "text/plain", []byte("hello")))
		if !strings.HasPrefix(raw, "HTTP/1.1 200 OK\r\n") {
			t.Errorf("bad status line: %q", raw)
		}
		if !strings.Contains(raw, "Content-Length: 5\r\n") {
			t.Errorf("expected Content-Length: 5: %q", raw)
		}
		if !strings.HasSuffix(raw, "\r\n\r\nhello") {
			t.Errorf("expected body after headers: %q", raw)
		}
	})

	t.Run("no content-length when body empty", func(t *testing.T) {
		raw := string(buildRawResponse(204, "No Content", nil, "", nil))
		if strings.Contains(raw, "Content-Length") {
			t.Errorf("empty body must not set Content-Length: %q", raw)
		}
	})
}

func TestComputeRiskScore(t *testing.T) {
	tests := []struct {
		name    string
		remarks []string
		status  int
		want    int
	}{
		{"sqli", []string{"sqli-error-based"}, 200, 40},
		{"xss plus 500", []string{"xss-reflected"}, 500, 40}, // 30 + 10
		{"unknown remark", []string{"whatever"}, 200, 5},
		{"capped at 100", []string{"sqli", "sqli", "lfi"}, 500, 100}, // 40+40+35+10 -> capped
		{"no remarks", nil, 200, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeRiskScore(tt.remarks, tt.status); got != tt.want {
				t.Errorf("computeRiskScore(%v,%d) = %d, want %d", tt.remarks, tt.status, got, tt.want)
			}
		})
	}
}

func TestHashStr(t *testing.T) {
	// Deterministic and 32 hex chars (128-bit prefix of sha256).
	a := hashStr([]byte("payload"))
	b := hashStr([]byte("payload"))
	if a != b {
		t.Error("hashStr must be deterministic")
	}
	if len(a) != 32 {
		t.Errorf("hashStr len = %d, want 32", len(a))
	}
	if hashStr([]byte("other")) == a {
		t.Error("different input should produce different hash")
	}
}
