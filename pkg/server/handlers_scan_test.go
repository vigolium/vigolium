package server

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/types"
)

// resolveScanOptions walks the same chain HandleRunScan walks for a given
// request, returning the final opts the runner would see. Profile loading
// is stubbed to a synthetic ProfileSettings so tests stay hermetic.
func resolveScanOptions(t *testing.T, req RunScanRequest, profileStrategy string) *types.Options {
	t.Helper()

	if err := validateRunScanRequest(req); err != nil {
		t.Fatalf("validateRunScanRequest: %v", err)
	}
	h := &Handlers{
		config:   ServerConfig{Concurrency: 50},
		settings: config.DefaultSettings(),
	}
	opts, err := h.buildRunScanOptions(req, "test-project")
	if err != nil {
		t.Fatalf("buildRunScanOptions: %v", err)
	}

	settings := config.DefaultSettings()
	if profileStrategy != "" {
		profile := &config.ProfileSettings{
			ScanningStrategy: &config.ProfileScanningStrategy{
				DefaultStrategy: profileStrategy,
			},
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			t.Fatalf("ApplyProfile: %v", err)
		}
	}

	if err := applyStrategy(opts, settings, req.Strategy, req.HeuristicsCheck); err != nil {
		t.Fatalf("applyStrategy: %v", err)
	}
	opts.OnlyPhase = req.Only
	opts.SkipPhases = append([]string(nil), req.Skip...)
	if err := runner.ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatalf("ApplyNativePhaseSelection: %v", err)
	}
	return opts
}

// TestHandleRunScan_ResolvesPhases is the regression guard for the silent
// profile clobber: applying a profile must not zero the per-strategy phase
// tables, so intensity=deep should resolve to all phases enabled.
func TestHandleRunScan_ResolvesPhases(t *testing.T) {
	cases := []struct {
		name              string
		req               RunScanRequest
		profileStrategy   string // mock profile's default_strategy; "" = no profile
		wantProfile       string // expected opts.ScanningProfile
		wantExternal      bool
		wantDiscover      bool
		wantSpidering     bool
		wantKnownIssue    bool
		wantSkipDynamic   bool
		wantSkipIngestion bool
	}{
		{
			name:            "intensity=deep enables every phase",
			req:             RunScanRequest{Targets: []string{"http://example.test/"}, Intensity: "deep"},
			profileStrategy: "deep",
			wantProfile:     "full",
			wantExternal:    true,
			wantDiscover:    true,
			wantSpidering:   true,
			wantKnownIssue:  true,
		},
		{
			name:            "intensity=quick clamps to lite",
			req:             RunScanRequest{Targets: []string{"http://example.test/"}, Intensity: "quick"},
			profileStrategy: "lite",
			wantProfile:     "quick",
			// lite leaves only dynamic-assessment on
		},
		{
			name:              "only=dynamic-assessment overrides strategy",
			req:               RunScanRequest{Targets: []string{"http://example.test/"}, Only: "dynamic-assessment"},
			wantSkipIngestion: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := resolveScanOptions(t, tc.req, tc.profileStrategy)

			if tc.wantProfile != "" && opts.ScanningProfile != tc.wantProfile {
				t.Errorf("ScanningProfile = %q, want %q", opts.ScanningProfile, tc.wantProfile)
			}
			if opts.ExternalHarvestEnabled != tc.wantExternal {
				t.Errorf("ExternalHarvestEnabled = %v, want %v", opts.ExternalHarvestEnabled, tc.wantExternal)
			}
			if opts.DiscoverEnabled != tc.wantDiscover {
				t.Errorf("DiscoverEnabled = %v, want %v", opts.DiscoverEnabled, tc.wantDiscover)
			}
			if opts.SpideringEnabled != tc.wantSpidering {
				t.Errorf("SpideringEnabled = %v, want %v", opts.SpideringEnabled, tc.wantSpidering)
			}
			if opts.KnownIssueScanEnabled != tc.wantKnownIssue {
				t.Errorf("KnownIssueScanEnabled = %v, want %v", opts.KnownIssueScanEnabled, tc.wantKnownIssue)
			}
			if opts.SkipDynamicAssessment != tc.wantSkipDynamic {
				t.Errorf("SkipDynamicAssessment = %v, want %v", opts.SkipDynamicAssessment, tc.wantSkipDynamic)
			}
			if opts.SkipIngestion != tc.wantSkipIngestion {
				t.Errorf("SkipIngestion = %v, want %v", opts.SkipIngestion, tc.wantSkipIngestion)
			}
		})
	}
}
