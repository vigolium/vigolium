package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/server"
	"github.com/vigolium/vigolium/pkg/types"
)

// resolveTestSettings returns default settings whose profiles_dir holds the
// three intensity profiles, so profile loading runs for real but hermetically.
func resolveTestSettings(t *testing.T, dir string) *config.Settings {
	t.Helper()
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ProfilesDir = dir
	return settings
}

func writeIntensityProfiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"quick":    "scanning_strategy:\n  default_strategy: lite\n",
		"standard": "scanning_strategy:\n  default_strategy: balanced\n",
		"full":     "scanning_strategy:\n  default_strategy: deep\nscanning_pace:\n  concurrency: 30\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// newResolveTestCmd parses args into a scan-shaped command bound to the same
// globals and pace knobs `vigolium scan` uses, restoring all of them afterwards.
func newResolveTestCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	swapGlobal(t, &globalStrategy, "")
	swapGlobal(t, &globalIntensity, "")
	swapGlobal(t, &globalScanningProfile, "")
	swapGlobal(t, &globalHeuristicsCheck, "")
	swapGlobal(t, &globalSkipHeuristics, false)
	swapGlobal(t, &globalScanningMaxDuration, time.Duration(0))
	swapGlobal(t, &globalConcurrency, defaultConcurrency)
	swapGlobal(t, &globalRateLimit, defaultRateLimit)
	swapGlobal(t, &globalMaxPerHost, defaultMaxPerHost)
	swapGlobal(t, &globalModuleIDs, nil)
	swapGlobal(t, &globalModules, nil)
	swapGlobal(t, &scanExportScope, scanExportScope)
	for _, k := range []*paceKnob{concurrencyKnob, rateLimitKnob, maxPerHostKnob} {
		k := k
		_ = k.Replace(nil)
		t.Cleanup(func() { _ = k.Replace(nil) })
	}

	cmd := &cobra.Command{Use: "scan"}
	fs := cmd.Flags()
	registerPaceFlags(fs)
	fs.StringVar(&globalStrategy, "strategy", "", "")
	fs.StringVar(&globalIntensity, "intensity", "", "")
	fs.StringVar(&globalScanningProfile, "scanning-profile", "", "")
	fs.StringVar(&globalHeuristicsCheck, "heuristics-check", "", "")
	fs.BoolVar(&globalSkipHeuristics, "skip-heuristics", false, "")
	swapGlobal(t, &scanOpts.Safe, false)
	registerScanningMaxDurationFlag(fs)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return cmd
}

// cliResolve runs the scan command's option resolution for args and returns
// the options and settings it produced.
func cliResolve(t *testing.T, profilesDir string, args ...string) (*types.Options, *config.Settings, string) {
	t.Helper()
	cmd := newResolveTestCmd(t, args...)
	opts := types.DefaultOptions()
	opts.Silent = true
	// What runScanCmd copies from the globals before resolution.
	opts.Concurrency = globalConcurrency
	opts.MaxPerHost = globalMaxPerHost
	opts.RateLimit = globalRateLimit
	opts.Safe = scanOpts.Safe
	settings := resolveTestSettings(t, profilesDir)
	name, err := resolveNativeScanOptions(cmd, settings, opts)
	if err != nil {
		t.Fatalf("resolveNativeScanOptions(%v): %v", args, err)
	}
	return opts, settings, name
}

// TestScanOptionsParityCLIvsREST: the same request resolves to the same pace,
// phases and heuristics whether it arrives as `vigolium scan` flags or as a
// POST /api/scans/run body. The two used to be separate copies, and REST ran
// `strategy: lite` at full speed.
func TestScanOptionsParityCLIvsREST(t *testing.T) {
	profiles := writeIntensityProfiles(t)
	target := []string{"http://example.test/"}
	cases := []struct {
		name string
		cli  []string
		rest server.RunScanRequest
	}{
		{"defaults", nil, server.RunScanRequest{Targets: target}},
		{"lite", []string{"--strategy", "lite"}, server.RunScanRequest{Targets: target, Strategy: "lite"}},
		{"lite with explicit concurrency", []string{"--strategy", "lite", "--concurrency", "40"},
			server.RunScanRequest{Targets: target, Strategy: "lite", Concurrency: 40}},
		{"lite with explicit rate limit and max per host", []string{"--strategy", "lite", "--rate-limit", "7", "--max-per-host", "3"},
			server.RunScanRequest{Targets: target, Strategy: "lite", RateLimit: 7, MaxPerHost: 3}},
		{"deep", []string{"--strategy", "deep"}, server.RunScanRequest{Targets: target, Strategy: "deep"}},
		{"intensity quick", []string{"--intensity", "quick"}, server.RunScanRequest{Targets: target, Intensity: "quick"}},
		{"intensity deep with profile pace", []string{"--intensity", "deep"}, server.RunScanRequest{Targets: target, Intensity: "deep"}},
		{"heuristics and max duration", []string{"--heuristics-check", "advanced", "--scanning-max-duration", "2h"},
			server.RunScanRequest{Targets: target, HeuristicsCheck: "advanced", ScanningMaxDuration: "2h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliOpts, cliSettings, cliStrategy := cliResolve(t, profiles, tc.cli...)

			restSettings := resolveTestSettings(t, profiles)
			restOpts, restStrategy, err := server.ResolveRunScanRequest(restSettings, types.DefaultConcurrency, tc.rest, "p")
			if err != nil {
				t.Fatalf("ResolveRunScanRequest: %v", err)
			}

			if cliStrategy != restStrategy.Name {
				t.Errorf("strategy: cli %q rest %q", cliStrategy, restStrategy.Name)
			}
			type view struct {
				Concurrency, RateLimit, MaxPerHost        int
				ExplicitC, ExplicitR, ExplicitH           bool
				Discover, Spider, KIS, External, SkipDA   bool
				Heuristics, Profile, Intensity            string
				DiscoverDur, SpiderDur, ScanMaxDuration   time.Duration
				PaceConcurrency, PaceRate, PaceMaxPerHost int
			}
			see := func(o *types.Options, s *config.Settings) view {
				return view{
					o.Concurrency, o.RateLimit, o.MaxPerHost,
					o.ConcurrencyExplicitlySet, o.RateLimitExplicitlySet, o.MaxPerHostExplicitlySet,
					o.DiscoverEnabled, o.SpideringEnabled, o.KnownIssueScanEnabled, o.ExternalHarvestEnabled, o.SkipDynamicAssessment,
					o.HeuristicsCheck, o.ScanningProfile, o.Intensity,
					o.DiscoverMaxDuration, o.SpideringMaxDuration, o.ScanMaxDuration,
					s.ScanningPace.Concurrency, s.ScanningPace.RateLimit, s.ScanningPace.MaxPerHost,
				}
			}
			if c, r := see(cliOpts, cliSettings), see(restOpts, restSettings); c != r {
				t.Errorf("CLI and REST resolved differently:\n cli  %+v\n rest %+v", c, r)
			}
		})
	}
}

// TestResolveNativeScanOptions_UnknownStrategyIsUsageError keeps exit 2.
func TestResolveNativeScanOptions_UnknownStrategyIsUsageError(t *testing.T) {
	cmd := newResolveTestCmd(t, "--strategy", "ludicrous")
	_, err := resolveNativeScanOptions(cmd, config.DefaultSettings(), types.DefaultOptions())
	if err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("err = %v, want a usage error", err)
	}
}

// TestMaxPerHostDefaultsAgree pins every max-per-host default to the one
// constant (decision D9: 40). They had drifted to 50/40/20/10, so scan,
// scan-url and the REST server ran the same target at different widths. The
// runner's own fallback is pinned by TestNewHostLimiter_DefaultsToSharedMaxPerHost.
func TestMaxPerHostDefaultsAgree(t *testing.T) {
	want := types.DefaultMaxPerHost
	if want != 40 {
		t.Fatalf("types.DefaultMaxPerHost = %d, decision D9 says 40", want)
	}
	limiter := ratelimit.NewHostRateLimiter(ratelimit.HostRateLimiterConfig{})
	defer func() { _ = limiter.Close() }()

	sites := map[string]int{
		"cli defaultMaxPerHost":                    defaultMaxPerHost,
		"types.DefaultOptions().MaxPerHost":        types.DefaultOptions().MaxPerHost,
		"config.DefaultScanningPaceConfig()":       config.DefaultScanningPaceConfig().MaxPerHost,
		"config.DefaultSettings().ScanningPace":    config.DefaultSettings().ScanningPace.MaxPerHost,
		"ratelimit.DefaultHostRateLimiterConfig()": ratelimit.DefaultHostRateLimiterConfig().MaxPerHost,
		"ratelimit zero-config fallback":           limiter.CeilingPerHost(),
	}
	if f := scanCmd.Flags().Lookup("max-per-host"); f != nil {
		n, err := strconv.Atoi(f.DefValue)
		if err != nil {
			t.Fatalf("--max-per-host DefValue %q: %v", f.DefValue, err)
		}
		sites["scan --max-per-host help default"] = n
	} else {
		t.Fatal("scan has no --max-per-host flag")
	}
	for site, got := range sites {
		if got != want {
			t.Errorf("%s = %d, want %d", site, got, want)
		}
	}
}

// TestResolveSafeAndMaxTime is RUN-1: --safe applies the embedded overlay
// (pace, 15m total budget, strict origin, GET/HEAD, browser interaction off,
// intrusive templates excluded) and turns risky payloads off even at deep
// intensity, typed flags still win, and a scan with no --max-time is bounded by
// scanning_pace.scan_max_duration (1h). --scanning-max-duration is an alias.
func TestResolveSafeAndMaxTime(t *testing.T) {
	profiles := writeIntensityProfiles(t)

	opts, _, _ := cliResolve(t, profiles)
	if opts.ScanMaxDuration != time.Hour {
		t.Fatalf("default total budget = %s, want 1h", opts.ScanMaxDuration)
	}

	opts, settings, _ := cliResolve(t, profiles, "--safe", "--intensity", "deep")
	if opts.ScanMaxDuration != 15*time.Minute {
		t.Errorf("--safe budget = %s, want 15m", opts.ScanMaxDuration)
	}
	if opts.Concurrency != 10 || opts.RateLimit != 20 || opts.MaxPerHost != 5 {
		t.Errorf("--safe pace = c%d r%d h%d, want 10/20/5", opts.Concurrency, opts.RateLimit, opts.MaxPerHost)
	}
	if got := settings.Scope.Methods; len(got) != 2 || got[0] != "GET" || got[1] != "HEAD" {
		t.Errorf("scope.methods = %v, want [GET HEAD]", got)
	}
	if settings.Scope.CLIOriginMode != "strict" {
		t.Errorf("origin mode = %q, want strict", settings.Scope.CLIOriginMode)
	}
	if sf := settings.Spidering.Interaction.SubmitForms; sf == nil || *sf {
		t.Error("--safe must turn browser form submission off")
	}
	if !slices.Contains(settings.KnownIssueScan.ExcludeTags, "intrusive") {
		t.Errorf("KIS exclude tags = %v, want intrusive excluded", settings.KnownIssueScan.ExcludeTags)
	}
	if runner.RiskyPayloadsAllowed(opts, settings) {
		t.Error("--safe must disable risky payloads even at --intensity deep")
	}

	opts, _, _ = cliResolve(t, profiles, "--safe", "--rate-limit", "50", "--max-time", "30m")
	if opts.RateLimit != 50 || opts.ScanMaxDuration != 30*time.Minute {
		t.Errorf("typed flags must win over --safe: rate=%d budget=%s", opts.RateLimit, opts.ScanMaxDuration)
	}
	opts, _, _ = cliResolve(t, profiles, "--scanning-max-duration", "2h")
	if opts.ScanMaxDuration != 2*time.Hour {
		t.Errorf("alias --scanning-max-duration = %s, want 2h", opts.ScanMaxDuration)
	}
}
