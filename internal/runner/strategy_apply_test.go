package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestApplyScanStrategy_Table pins the resolver every entry point shares:
// strategy phases, the pace ceiling (narrowing only knobs the caller did not
// set, never widening a gentler config) and the scanning_pace fold.
func TestApplyScanStrategy_Table(t *testing.T) {
	type pace struct{ concurrency, rateLimit, maxPerHost int }
	cases := []struct {
		name     string
		strategy string
		// configure tweaks the settings before resolution (e.g. a profile that
		// already set a gentler pace).
		configure func(*config.Settings)
		// caller-typed values and which of them count as explicit.
		typed    pace
		explicit ExplicitPace

		wantPace      pace
		wantDiscovery bool
		wantSpider    bool
		wantKIS       bool
		wantExternal  bool
	}{
		{
			name:     "lite narrows every unset knob to its ceiling",
			strategy: "lite",
			wantPace: pace{10, 20, 10},
		},
		{
			name:     "lite keeps explicit values (operator overrules the preset)",
			strategy: "lite",
			typed:    pace{40, 50, 30},
			explicit: ExplicitPace{Concurrency: true, RateLimit: true, MaxPerHost: true},
			wantPace: pace{40, 50, 30},
		},
		{
			name:     "lite narrows only the implicit knob",
			strategy: "lite",
			typed:    pace{40, 0, 0},
			explicit: ExplicitPace{Concurrency: true},
			wantPace: pace{40, 20, 10},
		},
		{
			name:     "a config already gentler than lite stays gentler",
			strategy: "lite",
			configure: func(s *config.Settings) {
				s.ScanningPace.Concurrency = 3
				s.ScanningPace.RateLimit = 5
				s.ScanningPace.MaxPerHost = 2
			},
			wantPace: pace{3, 5, 2},
		},
		{
			name:          "balanced runs at scanning_pace with every phase but harvest",
			strategy:      "balanced",
			wantPace:      pace{types.DefaultConcurrency, 100, types.DefaultMaxPerHost},
			wantDiscovery: true,
			wantSpider:    true,
			wantKIS:       true,
		},
		{
			name:          "deep opens every phase and imposes no ceiling",
			strategy:      "deep",
			wantPace:      pace{types.DefaultConcurrency, 100, types.DefaultMaxPerHost},
			wantDiscovery: true,
			wantSpider:    true,
			wantKIS:       true,
			wantExternal:  true,
		},
		{
			name:          "empty name falls back to default_strategy",
			strategy:      "",
			configure:     func(s *config.Settings) { s.ScanningStrategy.DefaultStrategy = "lite" },
			wantPace:      pace{10, 20, 10},
			wantDiscovery: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := config.DefaultSettings()
			if tc.configure != nil {
				tc.configure(settings)
			}
			opts := types.DefaultOptions()
			if tc.typed.concurrency > 0 {
				opts.Concurrency = tc.typed.concurrency
			}
			if tc.typed.rateLimit > 0 {
				opts.RateLimit = tc.typed.rateLimit
			}
			if tc.typed.maxPerHost > 0 {
				opts.MaxPerHost = tc.typed.maxPerHost
			}

			if _, err := ApplyScanStrategy(settings, opts, StrategyRequest{Name: tc.strategy, Explicit: tc.explicit}); err != nil {
				t.Fatalf("ApplyScanStrategy: %v", err)
			}
			if err := ApplyScanPace(settings, opts, tc.explicit); err != nil {
				t.Fatalf("ApplyScanPace: %v", err)
			}

			got := pace{opts.Concurrency, opts.RateLimit, opts.MaxPerHost}
			if got != tc.wantPace {
				t.Errorf("opts pace = %+v, want %+v", got, tc.wantPace)
			}
			// The runner reads non-explicit knobs from scanning_pace (host
			// limiter, per-phase concurrency), so the ceiling must land there too.
			if !tc.explicit.MaxPerHost && settings.ScanningPace.MaxPerHost != tc.wantPace.maxPerHost {
				t.Errorf("scanning_pace.max_per_host = %d, want %d", settings.ScanningPace.MaxPerHost, tc.wantPace.maxPerHost)
			}
			if tc.explicit.RateLimit && settings.ScanningPace.RateLimit != tc.typed.rateLimit {
				t.Errorf("explicit rate limit not written to scanning_pace: %d", settings.ScanningPace.RateLimit)
			}
			if opts.ConcurrencyExplicitlySet != tc.explicit.Concurrency ||
				opts.RateLimitExplicitlySet != tc.explicit.RateLimit ||
				opts.MaxPerHostExplicitlySet != tc.explicit.MaxPerHost {
				t.Errorf("explicit flags not recorded on opts: %+v", tc.explicit)
			}
			if opts.DiscoverEnabled != tc.wantDiscovery || opts.SpideringEnabled != tc.wantSpider ||
				opts.KnownIssueScanEnabled != tc.wantKIS || opts.ExternalHarvestEnabled != tc.wantExternal {
				t.Errorf("phases = discovery:%v spider:%v kis:%v external:%v",
					opts.DiscoverEnabled, opts.SpideringEnabled, opts.KnownIssueScanEnabled, opts.ExternalHarvestEnabled)
			}
		})
	}
}

func TestApplyScanStrategy_ExternalHarvestOverrideAndHeuristics(t *testing.T) {
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.ExternalHarvestEnabled = true
	if _, err := ApplyScanStrategy(settings, opts, StrategyRequest{
		Name:     "balanced",
		Explicit: ExplicitPace{ExternalHarvest: true},
	}); err != nil {
		t.Fatal(err)
	}
	if !opts.ExternalHarvestEnabled {
		t.Error("an explicit external-harvest must survive the strategy baseline")
	}
	if opts.HeuristicsCheck != "basic" {
		t.Errorf("HeuristicsCheck = %q, want config default basic", opts.HeuristicsCheck)
	}

	opts = types.DefaultOptions()
	if _, err := ApplyScanStrategy(settings, opts, StrategyRequest{HeuristicsCheck: "advanced", SkipHeuristics: true}); err != nil {
		t.Fatal(err)
	}
	if opts.HeuristicsCheck != "none" {
		t.Errorf("SkipHeuristics must win, got %q", opts.HeuristicsCheck)
	}
}

func TestApplyScanStrategy_UnknownStrategy(t *testing.T) {
	_, err := ApplyScanStrategy(config.DefaultSettings(), types.DefaultOptions(), StrategyRequest{Name: "ludicrous"})
	if !errors.Is(err, ErrUnknownStrategy) {
		t.Fatalf("want ErrUnknownStrategy, got %v", err)
	}
}

func TestApplyScanPace_DurationsAndValidation(t *testing.T) {
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.ScanMaxDuration = 2 * time.Hour
	ApplyScanSettingOverrides(settings, opts)
	if err := ApplyScanPace(settings, opts, ExplicitPace{}); err != nil {
		t.Fatal(err)
	}
	// discovery duration_factor 0.5 of the 2h budget.
	if opts.DiscoverMaxDuration != time.Hour {
		t.Errorf("DiscoverMaxDuration = %s, want 1h", opts.DiscoverMaxDuration)
	}

	opts = types.DefaultOptions()
	opts.SpideringMaxDuration = time.Minute
	if err := ApplyScanPace(settings, opts, ExplicitPace{SpideringMaxDuration: true}); err != nil {
		t.Fatal(err)
	}
	if opts.SpideringMaxDuration != time.Minute {
		t.Errorf("explicit spider duration replaced: %s", opts.SpideringMaxDuration)
	}

	settings.ScanningPace.Concurrency = -1
	if err := ApplyScanPace(settings, types.DefaultOptions(), ExplicitPace{}); err == nil {
		t.Error("an invalid scanning_pace must be an error")
	}
}

func TestApplyScanSettingOverrides(t *testing.T) {
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.OastURL = "https://oast.example.test"
	opts.ScopeOriginMode = "strict"
	ApplyScanSettingOverrides(settings, opts)
	if settings.OAST.OastURL != opts.OastURL {
		t.Errorf("OastURL = %q", settings.OAST.OastURL)
	}
	if settings.Scope.CLIOriginMode != "strict" {
		t.Errorf("CLIOriginMode = %q", settings.Scope.CLIOriginMode)
	}
}

// TestApplyIntensityAndProfile covers the profile precedence (explicit >
// intensity > config) and that every failure is an error rather than a scan
// without the profile the caller named.
func TestApplyIntensityAndProfile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("quick", "scanning_strategy:\n  default_strategy: lite\nscanning_pace:\n  concurrency: 7\n")
	write("mine", "scanning_pace:\n  concurrency: 9\n")

	newSettings := func() *config.Settings {
		s := config.DefaultSettings()
		s.ScanningStrategy.ProfilesDir = dir
		return s
	}

	t.Run("intensity maps to its profile", func(t *testing.T) {
		s, opts := newSettings(), types.DefaultOptions()
		path, err := ApplyIntensityAndProfile(s, opts, ProfileRequest{Intensity: "quick"})
		if err != nil {
			t.Fatal(err)
		}
		if path == "" || opts.ScanningProfile != "quick" || opts.Intensity != "quick" {
			t.Errorf("path=%q profile=%q intensity=%q", path, opts.ScanningProfile, opts.Intensity)
		}
		if s.ScanningStrategy.DefaultStrategy != "lite" || s.ScanningPace.Concurrency != 7 {
			t.Errorf("profile not applied: strategy=%q concurrency=%d", s.ScanningStrategy.DefaultStrategy, s.ScanningPace.Concurrency)
		}
	})

	t.Run("explicit profile wins over intensity", func(t *testing.T) {
		s, opts := newSettings(), types.DefaultOptions()
		if _, err := ApplyIntensityAndProfile(s, opts, ProfileRequest{Intensity: "quick", Profile: "mine"}); err != nil {
			t.Fatal(err)
		}
		if opts.ScanningProfile != "mine" || s.ScanningPace.Concurrency != 9 {
			t.Errorf("profile=%q concurrency=%d", opts.ScanningProfile, s.ScanningPace.Concurrency)
		}
	})

	t.Run("config profile applies when nothing is requested", func(t *testing.T) {
		s, opts := newSettings(), types.DefaultOptions()
		s.ScanningStrategy.ScanningProfile = "mine"
		if _, err := ApplyIntensityAndProfile(s, opts, ProfileRequest{}); err != nil {
			t.Fatal(err)
		}
		if opts.ScanningProfile != "mine" {
			t.Errorf("profile=%q", opts.ScanningProfile)
		}
	})

	t.Run("missing profile and bad intensity are errors", func(t *testing.T) {
		if _, err := ApplyIntensityAndProfile(newSettings(), types.DefaultOptions(), ProfileRequest{Profile: "absent"}); err == nil {
			t.Error("a missing profile must be an error")
		}
		if _, err := ApplyIntensityAndProfile(newSettings(), types.DefaultOptions(), ProfileRequest{Intensity: "ludicrous"}); err == nil {
			t.Error("an invalid intensity must be an error")
		}
	})

	t.Run("built-in profile falls back to the embedded copy", func(t *testing.T) {
		// RUN-7: a home whose profiles directory is empty (a mounted config,
		// no init) still resolves --intensity quick from the embed.
		s, opts := config.DefaultSettings(), types.DefaultOptions()
		s.ScanningStrategy.ProfilesDir = t.TempDir()
		if _, err := ApplyIntensityAndProfile(s, opts, ProfileRequest{Intensity: "quick"}); err != nil {
			t.Fatalf("empty profiles dir + intensity quick: %v", err)
		}
		if opts.ScanningProfile != "quick" {
			t.Errorf("profile=%q", opts.ScanningProfile)
		}
	})

	t.Run("no request and no config profile is a no-op", func(t *testing.T) {
		path, err := ApplyIntensityAndProfile(newSettings(), types.DefaultOptions(), ProfileRequest{})
		if err != nil || path != "" {
			t.Errorf("path=%q err=%v", path, err)
		}
	})
}

// TestResolveLaunchOptions_AppliesLite: the agent's run_scan with
// scanning_strategy lite used to record the name and run at full speed.
func TestResolveLaunchOptions_AppliesLite(t *testing.T) {
	settings := config.DefaultSettings()
	opts, err := resolveLaunchOptions(settings, LaunchParams{
		Targets:          []string{"http://example.test/"},
		ScanningStrategy: "lite",
		EnableDiscovery:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Concurrency != 10 || opts.RateLimit != 20 || opts.MaxPerHost != 10 {
		t.Errorf("pace = c%d r%d h%d, want lite's 10/20/10", opts.Concurrency, opts.RateLimit, opts.MaxPerHost)
	}
	if settings.ScanningPace.MaxPerHost != 10 {
		t.Errorf("scanning_pace.max_per_host = %d, want 10 (the host limiter reads it)", settings.ScanningPace.MaxPerHost)
	}
	if !opts.DiscoverEnabled || opts.SpideringEnabled || opts.KnownIssueScanEnabled {
		t.Errorf("launch phase toggles must win: discovery=%v spider=%v kis=%v",
			opts.DiscoverEnabled, opts.SpideringEnabled, opts.KnownIssueScanEnabled)
	}

	// An explicit concurrency survives the ceiling, as on the CLI.
	opts, err = resolveLaunchOptions(config.DefaultSettings(), LaunchParams{
		Targets: []string{"http://example.test/"}, ScanningStrategy: "lite", Concurrency: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Concurrency != 30 || !opts.ConcurrencyExplicitlySet {
		t.Errorf("explicit concurrency lost: %d", opts.Concurrency)
	}

	if _, err := resolveLaunchOptions(config.DefaultSettings(), LaunchParams{
		Targets: []string{"x"}, ScanningStrategy: "nope",
	}); !errors.Is(err, ErrUnknownStrategy) {
		t.Errorf("unknown strategy: %v", err)
	}
}

// TestNewHostLimiter_DefaultsToSharedMaxPerHost is the runner's half of
// TestMaxPerHostDefaultsAgree (pkg/cli): with nothing chosen the limiter runs
// at the one shared default rather than a private fallback.
func TestNewHostLimiter_DefaultsToSharedMaxPerHost(t *testing.T) {
	h := newHostLimiter(0, nil, true)
	defer func() { _ = h.Close() }()
	if got := h.CeilingPerHost(); got != types.DefaultMaxPerHost {
		t.Errorf("fallback max-per-host = %d, want %d", got, types.DefaultMaxPerHost)
	}
}
