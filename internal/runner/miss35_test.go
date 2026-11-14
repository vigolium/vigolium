package runner

import (
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestKnownIssueScanRateLimit_ExplicitOnly: the global 100 rps default no
// longer overrides the known-issue scan's own 20 rps; an explicit section or a
// typed --rate-limit still does.
func TestKnownIssueScanRateLimit_ExplicitOnly(t *testing.T) {
	settings := config.DefaultSettings()
	settings.ScanningPace.RateLimit = 100
	opts := types.DefaultOptions()
	opts.RateLimit = 100
	opts.RateLimitExplicitlySet = false
	if got := settings.ScanningPace.KnownIssueScanRateLimit(opts); got != config.KnownIssueScanDefaultRateLimit {
		t.Fatalf("implicit rate = %d, want the phase default %d", got, config.KnownIssueScanDefaultRateLimit)
	}
	opts.RateLimitExplicitlySet = true
	if got := settings.ScanningPace.KnownIssueScanRateLimit(opts); got != 100 {
		t.Fatalf("typed --rate-limit = %d, want 100", got)
	}
	settings.ScanningPace.KnownIssueScan.RateLimit = 7
	if got := settings.ScanningPace.KnownIssueScanRateLimit(opts); got != 7 {
		t.Fatalf("section rate = %d, want 7", got)
	}
	if got := planPhasePace(config.DefaultSettings(), types.DefaultOptions(), string(PhaseKnownIssueScan)); got == nil || got.RateLimit != config.KnownIssueScanDefaultRateLimit {
		t.Fatalf("plan pace = %+v, want the phase default rate", got)
	}
}

// TestFilterKISTargetsByScope: path-level scope applies to enriched targets.
func TestFilterKISTargetsByScope(t *testing.T) {
	sc := config.DefaultSettings().Scope
	sc.Path.Exclude = []string{"/admin/*"}
	m := config.NewScopeMatcher(sc, "https://app.test")
	kept, dropped := filterKISTargetsByScope(m, []string{"https://app.test", "https://app.test/api", "https://app.test/admin", "https://evil.test"})
	if dropped != 2 || !slices.Equal(kept, []string{"https://app.test", "https://app.test/api"}) {
		t.Fatalf("kept %v dropped %d", kept, dropped)
	}
	if k, d := filterKISTargetsByScope(nil, []string{"x"}); d != 0 || len(k) != 1 {
		t.Fatal("nil matcher keeps everything")
	}
}
