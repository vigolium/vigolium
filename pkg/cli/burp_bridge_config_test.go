package cli

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/burpbridge"
)

// internal/config cannot import pkg/burpbridge (burpbridge -> database -> config
// is an import cycle), so the bridge's default address is duplicated as a
// literal there. This test is the seam that keeps the copies honest.
func TestDefaultBurpBridgeURLMatchesBridge(t *testing.T) {
	if config.DefaultBurpBridgeURL != burpbridge.DefaultURL {
		t.Fatalf("config.DefaultBurpBridgeURL = %q, want burpbridge.DefaultURL %q",
			config.DefaultBurpBridgeURL, burpbridge.DefaultURL)
	}
	if got := config.DefaultServerConfig().BurpBridgeURL; got != burpbridge.DefaultURL {
		t.Fatalf("DefaultServerConfig().BurpBridgeURL = %q, want %q", got, burpbridge.DefaultURL)
	}
}

// The config fallback is gated on enable_burp_bridge: a config carrying only the
// default URL must not switch the bridge on by itself.
func TestBurpBridgeConfigFallbackRequiresEnable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flag    string
		enabled bool
		cfgURL  string
		want    string
	}{
		{"disabled by default", "", false, "http://127.0.0.1:9009", ""},
		{"enabled uses config url", "", true, "http://127.0.0.1:7777", "http://127.0.0.1:7777"},
		{"enabled empty url falls back to default", "", true, "", burpbridge.DefaultURL},
		{"flag wins over config", "http://127.0.0.1:8888", true, "http://127.0.0.1:7777", "http://127.0.0.1:8888"},
		{"flag wins while disabled", "http://127.0.0.1:8888", false, "http://127.0.0.1:7777", "http://127.0.0.1:8888"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.flag
			if got == "" && tc.enabled {
				got = firstNonEmptyString(tc.cfgURL, burpbridge.DefaultURL)
			}
			if got != tc.want {
				t.Fatalf("resolved bridge URL = %q, want %q", got, tc.want)
			}
		})
	}
}
