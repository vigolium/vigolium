package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// TestSwarmPresetDefaults_TriageAndIterations locks down the contract that
// task F encodes: balanced and deep run triage by default, quick doesn't,
// and the deep MaxIterations floor is at least 5. Regressions here mean
// the swarm silently dropped triage coverage on a normal run.
func TestSwarmPresetDefaults_TriageAndIterations(t *testing.T) {
	cases := []struct {
		intensity        agenttypes.Intensity
		wantTriage       bool
		minMaxIterations int
	}{
		{agenttypes.IntensityQuick, false, 1},
		{agenttypes.IntensityBalanced, true, 3},
		{agenttypes.IntensityDeep, true, 5},
	}
	for _, c := range cases {
		preset, ok := agenttypes.SwarmPresets[c.intensity]
		if !ok {
			t.Errorf("intensity %s missing from SwarmPresets", c.intensity)
			continue
		}
		if preset.Triage != c.wantTriage {
			t.Errorf("intensity %s: want Triage=%v, got %v", c.intensity, c.wantTriage, preset.Triage)
		}
		if preset.MaxIterations < c.minMaxIterations {
			t.Errorf("intensity %s: want MaxIterations >= %d, got %d",
				c.intensity, c.minMaxIterations, preset.MaxIterations)
		}
	}
}

// TestSwarmPresetDefaults_MaxPlanRecordsScale verifies task G's cap-scaling
// doesn't regress: the deep preset must allow ≥ balanced ≥ quick records
// into the planner, since deep is the "ship the full surface" intensity.
func TestSwarmPresetDefaults_MaxPlanRecordsScale(t *testing.T) {
	q := agenttypes.SwarmPresets[agenttypes.IntensityQuick].MaxPlanRecords
	b := agenttypes.SwarmPresets[agenttypes.IntensityBalanced].MaxPlanRecords
	d := agenttypes.SwarmPresets[agenttypes.IntensityDeep].MaxPlanRecords

	if q > b || b > d {
		t.Errorf("MaxPlanRecords must scale quick≤balanced≤deep, got quick=%d balanced=%d deep=%d", q, b, d)
	}
	if d < 50 {
		t.Errorf("deep MaxPlanRecords must be ≥50 (task G contract), got %d", d)
	}
}

// TestResolveSwarmIntensity_ExplicitTriageOverridesPreset confirms an
// operator can still force triage off on balanced/deep with --triage=false.
func TestResolveSwarmIntensity_ExplicitTriageOverridesPreset(t *testing.T) {
	got := ResolveSwarmIntensity(
		agenttypes.IntensityBalanced,
		agenttypes.SwarmIntensityPreset{Triage: false},
		map[string]bool{"triage": true}, // operator explicitly set --triage
	)
	if got.Triage != false {
		t.Errorf("explicit --triage=false should override preset, got Triage=%v", got.Triage)
	}
}
