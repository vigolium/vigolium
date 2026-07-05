package discovery

import (
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// TestBaselineKeyAndProbe_Fuzz verifies that for a FUZZ template the baseline is
// keyed at the SAME cache directory the real fuzzed hits key on (path.Dir-cleaned,
// so a bypass prefix collapses) while probing keeps the marker and bypass prefix.
func TestBaselineKeyAndProbe_Fuzz(t *testing.T) {
	e := &Engine{}
	tmpl, _ := url.Parse("https://host.example.com/%23/../FUZZ")
	keyDir, probe := e.baselineKeyAndProbe(tmpl)

	// A real fuzzed hit must key on the same directory as the learned baseline.
	hit, _ := url.Parse("https://host.example.com/%23/../metrics")
	wantKey := fingerprint.ExtractCacheKey(hit).Path
	if keyDir != wantKey {
		t.Errorf("baseline keyDir = %q, but the fuzzed hit keys on %q — they must match", keyDir, wantKey)
	}

	// The probe URL substitutes the marker (keeping the fingerprint layer
	// marker-agnostic) while preserving the bypass prefix on the wire.
	if strings.Contains(probe.EscapedPath(), fuzzMarker) {
		t.Errorf("probe should have substituted the FUZZ marker: %q", probe.EscapedPath())
	}
	if !strings.Contains(probe.EscapedPath(), fuzzBaselineToken) {
		t.Errorf("probe missing the baseline token: %q", probe.EscapedPath())
	}
	if !strings.HasPrefix(probe.EscapedPath(), "/%23/../") {
		t.Errorf("probe lost the bypass prefix: %q", probe.EscapedPath())
	}
}

func TestResolveFuzzProbeURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantURI string // expected RequestURI() of the resolved probe URL
		isFuzz  bool
	}{
		{
			name:    "bypass prefix, marker as last segment",
			in:      "https://host.example.com/%23/../FUZZ",
			wantURI: "/%23/../",
			isFuzz:  true,
		},
		{
			name:    "marker as last segment, no bypass",
			in:      "https://host.example.com/app/FUZZ",
			wantURI: "/app/",
			isFuzz:  true,
		},
		{
			name:    "marker embedded in filename",
			in:      "https://host.example.com/api/user_FUZZ.json",
			wantURI: "/api/",
			isFuzz:  true,
		},
		{
			name:    "marker at root",
			in:      "https://host.example.com/FUZZ",
			wantURI: "/",
			isFuzz:  true,
		},
		{
			name:    "marker in query keeps the endpoint path",
			in:      "https://host.example.com/search?q=FUZZ",
			wantURI: "/search",
			isFuzz:  true,
		},
		{
			name:    "no marker is a no-op",
			in:      "https://host.example.com/normal/path",
			wantURI: "/normal/path",
			isFuzz:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			got, isFuzz := resolveFuzzProbeURL(u)
			if isFuzz != tc.isFuzz {
				t.Errorf("isFuzz = %v, want %v", isFuzz, tc.isFuzz)
			}
			if got.RequestURI() != tc.wantURI {
				t.Errorf("RequestURI() = %q, want %q", got.RequestURI(), tc.wantURI)
			}
		})
	}
}
