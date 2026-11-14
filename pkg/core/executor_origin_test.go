package core

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func originItem(t *testing.T, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		t.Fatalf("build item for %q: %v", rawURL, err)
	}
	return rr
}

// TestOriginKeyFromItem_DistinguishesPortsAndSchemes locks in the per-origin
// claim key: the same hostname served on different ports/schemes must produce
// distinct keys (default ports normalized), so a ScanPerHost module isn't
// suppressed on :8443/:8080 after :443 claims the (module, host) pair.
func TestOriginKeyFromItem_DistinguishesPortsAndSchemes(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://example.com/", "https://example.com:443"},
		{"https://example.com:443/", "https://example.com:443"},
		{"https://example.com:8443/admin", "https://example.com:8443"},
		{"http://example.com/", "http://example.com:80"},
		{"http://example.com:80/", "http://example.com:80"},
		{"http://example.com:8080/", "http://example.com:8080"},
	}
	for _, tc := range cases {
		if got := httpmsg.OriginKey(originItem(t, tc.url)); got != tc.want {
			t.Errorf("httpmsg.OriginKey(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}

	// The three distinct origins of one hostname must not collide — this is the
	// multi-port suppression bug the origin key fixes.
	distinct := map[string]struct{}{}
	for _, u := range []string{"https://example.com/", "https://example.com:8443/", "http://example.com:8080/"} {
		distinct[httpmsg.OriginKey(originItem(t, u))] = struct{}{}
	}
	if len(distinct) != 3 {
		t.Fatalf("expected 3 distinct origin keys for a multi-port host, got %d: %v", len(distinct), distinct)
	}
}

// TestHostFromItem_MatchesURLWriteKey verifies the tech/content-class read key
// matches the URL host form the write paths use: bare host for default ports,
// host:port for non-default ports. Keying reads off the bare Service().Host()
// dropped the port and let a :443 stack gate modules on :8443.
func TestHostFromItem_MatchesURLWriteKey(t *testing.T) {
	cases := map[string]string{
		"https://example.com/":       "example.com",
		"https://example.com:8443/x": "example.com:8443",
		"http://example.com:8080/":   "example.com:8080",
	}
	for u, want := range cases {
		if got := hostFromItem(originItem(t, u)); got != want {
			t.Errorf("hostFromItem(%q) = %q, want %q", u, got, want)
		}
	}
}
