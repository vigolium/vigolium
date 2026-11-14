package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// TestBuildDeparosConfigExtractWords pins discovery.extract_words: unset means
// on at --intensity deep only; an explicit value wins either way (MISS-9).
func TestBuildDeparosConfigExtractWords(t *testing.T) {
	build := func(intensity string, v *bool) bool {
		settings := paceSettings(nil)
		settings.Discovery.ExtractWords = v
		r := &Runner{options: &types.Options{Targets: []string{"https://example.com"}, Intensity: intensity}, settings: settings}
		return r.buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).ExtractWords
	}
	on, off := true, false
	if build("balanced", nil) {
		t.Error("balanced, unset: want off")
	}
	if !build("deep", nil) {
		t.Error("deep, unset: want on")
	}
	if !build("quick", &on) {
		t.Error("explicit true: want on")
	}
	if build("deep", &off) {
		t.Error("explicit false at deep: want off")
	}
	// No settings at all: the intensity default still applies.
	bare := &Runner{options: &types.Options{Targets: []string{"https://example.com"}, Intensity: "deep"}}
	if !bare.buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).ExtractWords {
		t.Error("deep, no settings: want on")
	}
}
