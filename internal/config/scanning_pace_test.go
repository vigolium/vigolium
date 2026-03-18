package config

import (
	"testing"
	"time"
)

func TestResolvePhase_ConcurrencyFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		Discovery: PhasePace{
			ConcurrencyFactor: 0.5,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	if resolved.Concurrency != 25 {
		t.Errorf("expected concurrency 25, got %d", resolved.Concurrency)
	}
	if resolved.ConcurrencyFactor != 0.5 {
		t.Errorf("expected ConcurrencyFactor 0.5, got %f", resolved.ConcurrencyFactor)
	}
}

func TestResolvePhase_ConcurrencyFactor_Rounding(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 33,
		Spidering: PhasePace{
			ConcurrencyFactor: 0.5,
		},
	}
	resolved := cfg.ResolvePhase("spidering")
	// 33 * 0.5 = 16.5 → rounds to 17
	if resolved.Concurrency != 17 {
		t.Errorf("expected concurrency 17 (rounded), got %d", resolved.Concurrency)
	}
}

func TestResolvePhase_DurationFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			DurationFactor: 3.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	expected := 90 * time.Minute
	if resolved.MaxDuration != expected {
		t.Errorf("expected max_duration %v, got %v", expected, resolved.MaxDuration)
	}
	if resolved.DurationFactor != 3.0 {
		t.Errorf("expected DurationFactor 3.0, got %f", resolved.DurationFactor)
	}
}

func TestResolvePhase_DurationFactor_Fractional(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "30m",
		ExternalHarvester: PhasePace{
			DurationFactor: 0.2,
		},
	}
	resolved := cfg.ResolvePhase("external_harvester")
	expected := 6 * time.Minute
	if resolved.MaxDuration != expected {
		t.Errorf("expected max_duration %v, got %v", expected, resolved.MaxDuration)
	}
}

func TestResolvePhase_ExplicitOverridesFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Audit: PhasePace{
			Concurrency:       30,
			ConcurrencyFactor: 0.8, // ignored because concurrency is set
			MaxDuration:       "1h",
			DurationFactor:    2.0, // ignored because max_duration is set
		},
	}
	resolved := cfg.ResolvePhase("audit")
	if resolved.Concurrency != 30 {
		t.Errorf("expected concurrency 30 (explicit), got %d", resolved.Concurrency)
	}
	if resolved.ConcurrencyFactor != 0 {
		t.Errorf("expected ConcurrencyFactor 0 (not applied), got %f", resolved.ConcurrencyFactor)
	}
	if resolved.MaxDuration != time.Hour {
		t.Errorf("expected max_duration 1h (explicit), got %v", resolved.MaxDuration)
	}
	if resolved.DurationFactor != 0 {
		t.Errorf("expected DurationFactor 0 (not applied), got %f", resolved.DurationFactor)
	}
}

func TestResolvePhase_FactorZero_FallsThrough(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			ConcurrencyFactor: 0, // zero = not set, use common
			DurationFactor:    0, // zero = not set, use common
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	if resolved.Concurrency != 50 {
		t.Errorf("expected concurrency 50 (common fallback), got %d", resolved.Concurrency)
	}
	if resolved.MaxDuration != 30*time.Minute {
		t.Errorf("expected max_duration 30m (common fallback), got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_CommonMaxDuration(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "15m",
	}
	resolved := cfg.ResolvePhase("spidering")
	if resolved.MaxDuration != 15*time.Minute {
		t.Errorf("expected max_duration 15m from common, got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_NoCommonMaxDuration_FactorIgnored(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Discovery: PhasePace{
			DurationFactor: 2.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	// No common max_duration, so factor has nothing to scale
	if resolved.MaxDuration != 0 {
		t.Errorf("expected max_duration 0 (no common to scale), got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_ConcurrencyFactor_ZeroCommon(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 0,
		Discovery: PhasePace{
			ConcurrencyFactor: 2.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	// Common concurrency is 0, factor has nothing to scale
	if resolved.Concurrency != 0 {
		t.Errorf("expected concurrency 0, got %d", resolved.Concurrency)
	}
}

func TestValidate_NegativeConcurrencyFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Discovery: PhasePace{
			ConcurrencyFactor: -1.0,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative concurrency_factor")
	}
}

func TestValidate_NegativeDurationFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Spidering: PhasePace{
			DurationFactor: -0.5,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative duration_factor")
	}
}

func TestValidate_InvalidCommonMaxDuration(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "not-a-duration",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid common max_duration")
	}
}

func TestDefaultScanningPaceConfig(t *testing.T) {
	cfg := DefaultScanningPaceConfig()

	if cfg.MaxDuration != "2h" {
		t.Errorf("expected default max_duration '2h', got %q", cfg.MaxDuration)
	}

	// Verify per-phase duration factors are set
	tests := []struct {
		phase  string
		factor float64
	}{
		{"known-issue-scan", 3.0},
		{"spidering", 0.15},
		{"external_harvester", 0.2},
		{"audit", 1.0},
	}
	for _, tt := range tests {
		resolved := cfg.ResolvePhase(tt.phase)
		if resolved.DurationFactor != tt.factor {
			t.Errorf("phase %s: expected duration_factor %v, got %v", tt.phase, tt.factor, resolved.DurationFactor)
		}
		if resolved.MaxDuration == 0 {
			t.Errorf("phase %s: expected non-zero resolved max_duration", tt.phase)
		}
	}

	// Discovery has no per-phase factor, should inherit common max_duration directly
	disc := cfg.ResolvePhase("discovery")
	if disc.MaxDuration != 2*time.Hour {
		t.Errorf("discovery: expected max_duration 2h (common), got %v", disc.MaxDuration)
	}
	if disc.DurationFactor != 0 {
		t.Errorf("discovery: expected duration_factor 0, got %v", disc.DurationFactor)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			ConcurrencyFactor: 0.5,
			DurationFactor:    2.0,
		},
		Spidering: PhasePace{
			DurationFactor: 1.0,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}
