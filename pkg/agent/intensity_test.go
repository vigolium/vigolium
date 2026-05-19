package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// TestAutopilotPresets_BrowserOnEverywhere guards the operator-facing
// promise that autopilot can reach for browser-assisted probing at every
// intensity. If a preset accidentally regresses to Browser=false the agent
// silently loses that capability with no error — the test is the contract.
func TestAutopilotPresets_BrowserOnEverywhere(t *testing.T) {
	for _, intensity := range []agenttypes.Intensity{
		agenttypes.IntensityQuick, agenttypes.IntensityBalanced, agenttypes.IntensityDeep,
	} {
		preset := agenttypes.AutopilotPresets[intensity]
		assert.Truef(t, preset.Browser,
			"intensity %q must have Browser=true; CLI-side preset flip relies on this", intensity)
	}
}

// TestAutopilotPresets_NativeScanStrategy pins the intensity → strategy
// mapping the prescan helper consumes. Changing these values changes
// observable scan depth for every target-only autopilot run.
func TestAutopilotPresets_NativeScanStrategy(t *testing.T) {
	for _, tc := range []struct {
		intensity agenttypes.Intensity
		want      string
	}{
		{agenttypes.IntensityQuick, agenttypes.ScanStrategyLite},
		{agenttypes.IntensityBalanced, agenttypes.ScanStrategyBalanced},
		{agenttypes.IntensityDeep, agenttypes.ScanStrategyDeep},
	} {
		got := agenttypes.AutopilotPresets[tc.intensity].NativeScanStrategy
		assert.Equalf(t, tc.want, got,
			"intensity %q should map to scanning_strategy %q", tc.intensity, tc.want)
	}
}

// TestResolveAutopilotIntensity_NoPrescanOverride confirms an explicit
// --no-prescan flag wins over the preset default (which is false). Without
// this wiring the flag would be silently ignored.
func TestResolveAutopilotIntensity_NoPrescanOverride(t *testing.T) {
	out := ResolveAutopilotIntensity(agenttypes.IntensityBalanced,
		agenttypes.AutopilotIntensityPreset{NoPrescan: true},
		map[string]bool{"no-prescan": true})
	assert.True(t, out.NoPrescan, "explicit --no-prescan must override preset")
}

// TestResolveAutopilotIntensity_NoPrescanDefault confirms that without the
// changed flag the resolved value comes from the preset (false today).
// Pairs with the override test above to lock both branches.
func TestResolveAutopilotIntensity_NoPrescanDefault(t *testing.T) {
	out := ResolveAutopilotIntensity(agenttypes.IntensityBalanced,
		agenttypes.AutopilotIntensityPreset{NoPrescan: true}, // user value ignored
		map[string]bool{})
	assert.False(t, out.NoPrescan, "preset default must apply when --no-prescan is not set")
}

// TestResolveAutopilotIntensity_StrategyPropagates confirms the
// NativeScanStrategy preset value flows through unchanged — the resolver
// does not expose a per-call override for it (intensity is the only knob).
func TestResolveAutopilotIntensity_StrategyPropagates(t *testing.T) {
	for _, tc := range []struct {
		intensity agenttypes.Intensity
		want      string
	}{
		{agenttypes.IntensityQuick, agenttypes.ScanStrategyLite},
		{agenttypes.IntensityBalanced, agenttypes.ScanStrategyBalanced},
		{agenttypes.IntensityDeep, agenttypes.ScanStrategyDeep},
	} {
		out := ResolveAutopilotIntensity(tc.intensity,
			agenttypes.AutopilotIntensityPreset{Timeout: time.Hour}, nil)
		assert.Equalf(t, tc.want, out.NativeScanStrategy,
			"intensity %q must propagate strategy %q", tc.intensity, tc.want)
	}
}
