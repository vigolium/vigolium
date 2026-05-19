package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

func TestNormalizeNativePhase_Aliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"deparos", "discovery"},
		{"discover", "discovery"},
		{"spitolas", "spidering"},
		{"ext", "extension"},
		{"audit", "dynamic-assessment"},
		{"dast", "dynamic-assessment"},
		{"assessment", "dynamic-assessment"},
		{"dynamic-assessment", "dynamic-assessment"},
		{"discovery", "discovery"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		if got := NormalizeNativePhase(tt.input); got != tt.want {
			t.Errorf("NormalizeNativePhase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestApplyNativePhaseSelection_OnlyPhase(t *testing.T) {
	type want struct {
		onlyPhase             string
		discoverEnabled       bool
		spideringEnabled      bool
		externalHarvest       bool
		knownIssue            bool
		skipIngestion         bool
		skipDynamicAssessment bool
		extensionsOnly        bool
	}
	tests := []struct {
		name  string
		input string
		want  want
	}{
		{
			name:  "single spidering",
			input: "spidering",
			want: want{
				onlyPhase:             "spidering",
				spideringEnabled:      true,
				skipIngestion:         true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "single discovery keeps ingestion",
			input: "discovery",
			want: want{
				onlyPhase:             "discovery",
				discoverEnabled:       true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "comma-separated spidering and discovery",
			input: "spidering,discovery",
			want: want{
				onlyPhase:             "spidering,discovery",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "alias normalization with whitespace",
			input: "spitolas, deparos",
			want: want{
				onlyPhase:             "spidering,discovery",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "spidering plus dynamic-assessment runs both",
			input: "spidering,dynamic-assessment",
			want: want{
				onlyPhase:        "spidering,dynamic-assessment",
				spideringEnabled: true,
				skipIngestion:    true,
			},
		},
		{
			name:  "extension flips ExtensionsOnly",
			input: "extension",
			want: want{
				onlyPhase:      "extension",
				skipIngestion:  true,
				extensionsOnly: true,
			},
		},
		{
			name:  "duplicates collapse",
			input: "discovery,discovery,spidering",
			want: want{
				onlyPhase:             "discovery,spidering",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &types.Options{OnlyPhase: tt.input}
			if err := ApplyNativePhaseSelection(opts, nil); err != nil {
				t.Fatalf("ApplyNativePhaseSelection: %v", err)
			}
			if opts.OnlyPhase != tt.want.onlyPhase {
				t.Errorf("OnlyPhase = %q, want %q", opts.OnlyPhase, tt.want.onlyPhase)
			}
			if opts.DiscoverEnabled != tt.want.discoverEnabled {
				t.Errorf("DiscoverEnabled = %v, want %v", opts.DiscoverEnabled, tt.want.discoverEnabled)
			}
			if opts.SpideringEnabled != tt.want.spideringEnabled {
				t.Errorf("SpideringEnabled = %v, want %v", opts.SpideringEnabled, tt.want.spideringEnabled)
			}
			if opts.ExternalHarvestEnabled != tt.want.externalHarvest {
				t.Errorf("ExternalHarvestEnabled = %v, want %v", opts.ExternalHarvestEnabled, tt.want.externalHarvest)
			}
			if opts.KnownIssueScanEnabled != tt.want.knownIssue {
				t.Errorf("KnownIssueScanEnabled = %v, want %v", opts.KnownIssueScanEnabled, tt.want.knownIssue)
			}
			if opts.SkipIngestion != tt.want.skipIngestion {
				t.Errorf("SkipIngestion = %v, want %v", opts.SkipIngestion, tt.want.skipIngestion)
			}
			if opts.SkipDynamicAssessment != tt.want.skipDynamicAssessment {
				t.Errorf("SkipDynamicAssessment = %v, want %v", opts.SkipDynamicAssessment, tt.want.skipDynamicAssessment)
			}
			if opts.ExtensionsOnly != tt.want.extensionsOnly {
				t.Errorf("ExtensionsOnly = %v, want %v", opts.ExtensionsOnly, tt.want.extensionsOnly)
			}
		})
	}
}

func TestApplyNativePhaseSelection_OnlyPhaseErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"unknown phase", "bogus"},
		{"mixed valid + invalid", "discovery,bogus"},
		{"only commas", ",,,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &types.Options{OnlyPhase: tt.input}
			if err := ApplyNativePhaseSelection(opts, nil); err == nil {
				t.Errorf("expected error for input %q", tt.input)
			}
		})
	}
}
