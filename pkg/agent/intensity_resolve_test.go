package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// The deep-chain / explicit-modes / single-mode collapse cases for
// ResolveAuditDriverIntensity are covered in audit_modes_test.go. These cover
// the remaining branches: unknown-intensity fallback and commit-depth override.

func TestResolveAuditDriverIntensity_UnknownIntensityFallsBackToBalanced(t *testing.T) {
	got := ResolveAuditDriverIntensity(agenttypes.Intensity("warp"), agenttypes.AuditDriverIntensityPreset{}, nil)
	if got.Mode != "balanced" {
		t.Errorf("unknown intensity should fall back to balanced, got %q", got.Mode)
	}
}

func TestResolveAuditDriverIntensity_CommitDepthAndTimeoutOverride(t *testing.T) {
	current := agenttypes.AuditDriverIntensityPreset{CommitDepth: 99}
	got := ResolveAuditDriverIntensity(agenttypes.IntensityQuick, current,
		map[string]bool{"commit-depth": true})
	if got.CommitDepth != 99 {
		t.Errorf("CommitDepth = %d, want 99 (override)", got.CommitDepth)
	}
}

func TestResolveSwarmIntensity_NoChangeIsPurePreset(t *testing.T) {
	balanced := agenttypes.SwarmPresets[agenttypes.IntensityBalanced]
	pure := ResolveSwarmIntensity(agenttypes.IntensityBalanced,
		agenttypes.SwarmIntensityPreset{MaxIterations: 999}, nil)
	if pure.MaxIterations != balanced.MaxIterations {
		t.Errorf("no-change should keep preset MaxIterations %d, got %d", balanced.MaxIterations, pure.MaxIterations)
	}
}

func TestResolveSwarmIntensity_MultiFieldOverrides(t *testing.T) {
	current := agenttypes.SwarmIntensityPreset{
		MaxIterations:    42,
		Discover:         true,
		MaxPlanRecords:   7,
		MasterBatchSize:  3,
		BatchConcurrency: 2,
		ProbeConcurrency: 9,
	}
	got := ResolveSwarmIntensity(agenttypes.IntensityBalanced, current, map[string]bool{
		"max-iterations":    true,
		"discover":          true,
		"max-plan-records":  true,
		"master-batch-size": true,
		"batch-concurrency": true,
		"probe-concurrency": true,
	})
	if got.MaxIterations != 42 || !got.Discover || got.MaxPlanRecords != 7 ||
		got.MasterBatchSize != 3 || got.BatchConcurrency != 2 || got.ProbeConcurrency != 9 {
		t.Errorf("overrides not all applied: %+v", got)
	}
}

func TestResolveSwarmIntensity_UnknownFallsBackToBalanced(t *testing.T) {
	balanced := agenttypes.SwarmPresets[agenttypes.IntensityBalanced]
	got := ResolveSwarmIntensity(agenttypes.Intensity("zzz"), agenttypes.SwarmIntensityPreset{}, nil)
	if got.MaxIterations != balanced.MaxIterations {
		t.Errorf("unknown intensity should fall back to balanced preset")
	}
}

func TestResolveAutopilotIntensity_UnknownFallsBackToBalanced(t *testing.T) {
	balanced := agenttypes.AutopilotPresets[agenttypes.IntensityBalanced]
	got := ResolveAutopilotIntensity(agenttypes.Intensity("warp"), agenttypes.AutopilotIntensityPreset{}, nil)
	if got.MaxCommands != balanced.MaxCommands {
		t.Errorf("unknown intensity should use balanced preset (MaxCommands %d), got %d",
			balanced.MaxCommands, got.MaxCommands)
	}
}

func TestResolveAutopilotIntensity_MultiFieldOverrides(t *testing.T) {
	current := agenttypes.AutopilotIntensityPreset{
		MaxCommands:     12345,
		AuditDriverMode: "deep",
	}
	got := ResolveAutopilotIntensity(agenttypes.IntensityBalanced, current, map[string]bool{
		"max-commands": true,
		"audit-mode":   true,
	})
	if got.MaxCommands != 12345 {
		t.Errorf("MaxCommands = %d, want overridden 12345", got.MaxCommands)
	}
	if got.AuditDriverMode != "deep" {
		t.Errorf("AuditDriverMode = %q, want deep (override)", got.AuditDriverMode)
	}
}

func TestResolveNativeScanIntensity(t *testing.T) {
	t.Run("valid intensities map to profiles", func(t *testing.T) {
		for _, tc := range []struct {
			in      string
			profile string
		}{
			{"quick", agenttypes.NativeScanIntensityProfiles[agenttypes.IntensityQuick]},
			{"balanced", agenttypes.NativeScanIntensityProfiles[agenttypes.IntensityBalanced]},
			{"deep", agenttypes.NativeScanIntensityProfiles[agenttypes.IntensityDeep]},
		} {
			profile, resolved, err := ResolveNativeScanIntensity(tc.in)
			if err != nil {
				t.Fatalf("ResolveNativeScanIntensity(%q) error: %v", tc.in, err)
			}
			if profile != tc.profile {
				t.Errorf("profile = %q, want %q", profile, tc.profile)
			}
			if resolved != tc.in {
				t.Errorf("resolved = %q, want %q", resolved, tc.in)
			}
		}
	})

	t.Run("invalid intensity errors", func(t *testing.T) {
		if _, _, err := ResolveNativeScanIntensity("ludicrous"); err == nil {
			t.Error("expected error for invalid intensity")
		}
	})
}
