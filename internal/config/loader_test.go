package config

import (
	"os"
	"testing"
)

func TestExpandEnvVars(t *testing.T) {
	const testVar = "VIGOLIUM_TEST_EXPAND_VAR"

	tests := []struct {
		name   string
		input  string
		envVal string // empty means unset
		want   string
	}{
		{
			name:  "plain string no vars",
			input: "oast.pro",
			want:  "oast.pro",
		},
		{
			name:   "simple var set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "simple var unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR}",
			want:  "",
		},
		{
			name:   "default when var is set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			want:  "fallback",
		},
		{
			name:  "empty default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-}",
			want:  "",
		},
		{
			name:  "default with special chars",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-https://oast.example.com}",
			want:  "https://oast.example.com",
		},
		{
			name:   "mixed text and var with default",
			input:  "server: ${VIGOLIUM_TEST_EXPAND_VAR:-oast.pro}:443",
			envVal: "my.server",
			want:   "server: my.server:443",
		},
		{
			name:  "multiple vars with defaults",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-a}/${VIGOLIUM_TEST_EXPAND_VAR:-b}",
			want:  "a/b",
		},
		{
			name:   "dollar-var syntax (no default support)",
			input:  "$VIGOLIUM_TEST_EXPAND_VAR",
			envVal: "val",
			want:   "val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv(testVar)
			if tt.envVal != "" {
				t.Setenv(testVar, tt.envVal)
			}

			got := ExpandEnvVars(tt.input)
			if got != tt.want {
				t.Errorf("ExpandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestApplyProfile_PreservesStrategyPhaseTables guards against the regression
// where a profile that only meant to set default_strategy would silently
// zero the per-strategy phase tables (Lite/Balanced/Deep) via a YAML
// round-trip. After the fix, a profile that omits those tables must leave
// them untouched.
func TestApplyProfile_PreservesStrategyPhaseTables(t *testing.T) {
	settings := DefaultSettings()
	// Sanity: defaults populate Balanced with discovery+spidering+known-issue+dynamic enabled.
	if !settings.ScanningStrategy.Balanced.DynamicAssessment {
		t.Fatalf("precondition failed: default Balanced.DynamicAssessment should be true")
	}
	if !settings.ScanningStrategy.Balanced.Discovery {
		t.Fatalf("precondition failed: default Balanced.Discovery should be true")
	}
	if !settings.ScanningStrategy.Deep.ExternalHarvesting {
		t.Fatalf("precondition failed: default Deep.ExternalHarvesting should be true")
	}

	// Profile that only nudges default_strategy — the shape every bundled
	// profile under public/presets/profiles/ uses.
	profile := &ProfileSettings{
		ScanningStrategy: &ProfileScanningStrategy{
			DefaultStrategy: "deep",
		},
	}

	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if settings.ScanningStrategy.DefaultStrategy != "deep" {
		t.Errorf("DefaultStrategy = %q, want %q", settings.ScanningStrategy.DefaultStrategy, "deep")
	}
	if !settings.ScanningStrategy.Balanced.DynamicAssessment {
		t.Errorf("Balanced.DynamicAssessment was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.Discovery {
		t.Errorf("Balanced.Discovery was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.Spidering {
		t.Errorf("Balanced.Spidering was clobbered to false")
	}
	if !settings.ScanningStrategy.Balanced.KnownIssueScan {
		t.Errorf("Balanced.KnownIssueScan was clobbered to false")
	}
	if !settings.ScanningStrategy.Deep.ExternalHarvesting {
		t.Errorf("Deep.ExternalHarvesting was clobbered to false")
	}

	// Heuristics-check should also be merge-only (not clobbered) when absent.
	if profile.ScanningStrategy.HeuristicsCheck == "" &&
		settings.ScanningStrategy.HeuristicsCheck == "" {
		t.Errorf("HeuristicsCheck was clobbered from default to empty")
	}
}

// TestApplyProfile_HeuristicsCheckOverride confirms the explicit-merge path
// honors a profile that DOES set heuristics_check.
func TestApplyProfile_HeuristicsCheckOverride(t *testing.T) {
	settings := DefaultSettings()
	settings.ScanningStrategy.HeuristicsCheck = "basic"

	profile := &ProfileSettings{
		ScanningStrategy: &ProfileScanningStrategy{
			HeuristicsCheck: "advanced",
		},
	}

	if err := ApplyProfile(settings, profile); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if settings.ScanningStrategy.HeuristicsCheck != "advanced" {
		t.Errorf("HeuristicsCheck = %q, want %q", settings.ScanningStrategy.HeuristicsCheck, "advanced")
	}
}
