package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// explicitScanPace reports which pace knobs the operator typed on this command.
//
// globalChanged, not cmd.Flags().Changed, for the three pace dials: pflag marks
// a flag Changed when only its PHASE-QUALIFIED form was typed, and a per-phase
// value is not an operator overruling the strategy's invocation-wide ceiling.
func explicitScanPace(cmd *cobra.Command) runner.ExplicitPace {
	changed := func(name string) bool {
		f := cmd.Flags().Lookup(name)
		return f != nil && f.Changed
	}
	return runner.ExplicitPace{
		Concurrency:          concurrencyKnob.globalChanged(),
		RateLimit:            rateLimitKnob.globalChanged(),
		MaxPerHost:           maxPerHostKnob.globalChanged(),
		ExternalHarvest:      changed("external-harvest"),
		DiscoverMaxDuration:  changed("discover-max-time"),
		SpideringMaxDuration: changed("spider-max-time"),
		MaxRequests:          changed("max-requests"),
		MaxRequestsPerHost:   changed("max-requests-per-host"),
	}
}

// resolveNativeScanOptions runs the shared scan-options resolution for the scan
// command (the ordering contract is documented in runner/strategy_apply.go):
// intensity/profile → settings overrides → strategy (explicit rate limit,
// phases, pace ceiling, heuristics) → --only/--skip → per-phase qualifiers →
// scanning_pace fold. REST and the agent launcher call the same runner
// functions, so one request resolves to one pace on every entry point.
//
// It returns the resolved strategy name ("" when none applied). Nothing here
// writes files or touches the network beyond reading a named profile.
func resolveNativeScanOptions(cmd *cobra.Command, settings *config.Settings, opts *types.Options) (string, error) {
	explicit := explicitScanPace(cmd)
	if err := runner.ValidateMaxModuleTier(opts.MaxModuleTier); err != nil {
		return "", asUsageError(err)
	}
	if err := runner.ValidateMaxModuleTier(settings.DynamicAssessment.MaxModuleTier); err != nil {
		return "", asUsageError(fmt.Errorf("dynamic-assessment.max_module_tier: %w", err))
	}

	profileReq := runner.ProfileRequest{Profile: globalScanningProfile}
	if cmd.Flags().Changed("intensity") {
		profileReq.Intensity = globalIntensity
	}
	profilePath, err := runner.ApplyIntensityAndProfile(settings, opts, profileReq)
	if err != nil {
		return "", err
	}
	if profilePath != "" {
		zap.L().Info("Applied scanning profile", zap.String("profile", opts.ScanningProfile), zap.String("path", profilePath))
	}
	// --safe narrows the profile; typed flags (applied below) still win.
	if err := runner.ApplySafePreset(settings, opts); err != nil {
		return "", err
	}

	if maxTimeTyped(cmd) && globalScanningMaxDuration > 0 {
		opts.ScanMaxDuration = globalScanningMaxDuration
	}
	runner.ApplyScanSettingOverrides(settings, opts)
	runner.ApplyDefaultScanBudget(settings, opts)

	strategy, err := runner.ApplyScanStrategy(settings, opts, runner.StrategyRequest{
		Name:            globalStrategy,
		HeuristicsCheck: globalHeuristicsCheck,
		SkipHeuristics:  globalSkipHeuristics,
		Explicit:        explicit,
	})
	if err != nil {
		if errors.Is(err, runner.ErrUnknownStrategy) {
			return "", asUsageError(err)
		}
		return "", err
	}
	if strategy.Name != "" {
		zap.L().Debug("Applied scanning strategy",
			zap.String("strategy", strategy.Name),
			zap.Bool("external_harvest", opts.ExternalHarvestEnabled))
	}

	// A hand-picked module selection (--module-id / -m) implies a targeted,
	// low-noise scan, so auto-skip the broad known-issue-scan pass before phase
	// selection resolves it. Must run after the strategy sets KnownIssueScanEnabled
	// and before ApplyNativePhaseSelection consumes SkipPhases.
	autoSkipKnownIssueScanForModuleSelection(opts)

	// Before ApplyNativePhaseSelection: it applies the probe phase's own
	// defaults, and needs to know whether --record-redirect-chain was typed.
	if err := applyProbeFlags(opts, cmd); err != nil {
		return "", err
	}
	if err := runner.ApplyNativePhaseSelection(opts, func(enabled bool) {
		settings.DynamicAssessment.Extensions.Enabled = enabled
	}); err != nil {
		return "", err
	}
	warnInertProbeFlags(opts, cmd)
	if err := applyExportScope(opts); err != nil {
		return "", err
	}
	if opts.OnlyPhase != "" {
		zap.L().Info("Phase isolation active", zap.String("only", opts.OnlyPhase))
	}
	if len(opts.SkipPhases) > 0 {
		zap.L().Info("Phases skipped", zap.Strings("skip", opts.SkipPhases))
	}

	// Per-phase pace qualifiers (`--rate-limit known-issue-scan=20`) land in the
	// matching scanning_pace section, so ResolvePhase stays the one place
	// per-phase pace is merged. Applied after the phase selection is settled so a
	// qualifier naming a phase this run skips can be reported.
	applyPhasePaceOverrides(settings, opts)

	if err := runner.ApplyScanPace(settings, opts, explicit); err != nil {
		return "", err
	}
	return strategy.Name, nil
}

// validateLightweightScanTuning rejects a bad --intensity or a negative
// --scanning-max-duration on scan-url / scan-request before any network or
// database work, on either path (the Runner path would only find out after
// loading settings; the direct path never resolves the intensity).
func validateLightweightScanTuning() error {
	if v := strings.TrimSpace(globalIntensity); v != "" {
		if _, err := agenttypes.ValidateIntensity(v); err != nil {
			return asUsageError(err)
		}
	}
	if globalScanningMaxDuration < 0 {
		return usageErrorf("--scanning-max-duration must not be negative, got %s", globalScanningMaxDuration)
	}
	if err := runner.ValidateMaxModuleTier(scanOpts.MaxModuleTier); err != nil {
		return asUsageError(err)
	}
	return nil
}

// resolveLightweightScanOptions is the shared resolver's share of a scan-url /
// scan-request run through the Runner (runRunnerScan): intensity → profile,
// then the settings-backed overrides (--oast-url, --scope-origin,
// --scanning-max-duration), then — only when an intensity applied a profile —
// the profile's scanning_pace folded into the knobs not typed.
//
// The strategy step is deliberately not run: a strategy (the configured
// default, or the one the intensity's profile names) turns whole phases on and
// off, and these commands scan the one request they were given; phases are
// opted into with --discover/--spider/... instead. Without an intensity the
// profile and pace steps are skipped too, so a plain -S/-o run keeps
// scanning with exactly the flags it was given.
func resolveLightweightScanOptions(settings *config.Settings, opts *types.Options) error {
	profiled := false
	if opts.Intensity != "" {
		profilePath, err := runner.ApplyIntensityAndProfile(settings, opts, runner.ProfileRequest{Intensity: opts.Intensity})
		if err != nil {
			return err
		}
		if profilePath != "" {
			profiled = true
			zap.L().Info("Applied scanning profile", zap.String("profile", opts.ScanningProfile), zap.String("path", profilePath))
		}
		// --intensity deep turns on the alternate-port sweep of the CLI target
		// hosts on `scan`. Here the input is one request, not a host to
		// enumerate; a phase flag (which crawls from the target URL) keeps it.
		if !hasPhaseFlags() {
			opts.SkipPortSweep = true
		}
	}
	if err := runner.ApplySafePreset(settings, opts); err != nil {
		return err
	}
	runner.ApplyScanSettingOverrides(settings, opts)
	runner.ApplyDefaultScanBudget(settings, opts)
	if opts.Safe {
		profiled = true // fold the overlay's pace into the knobs not typed
	}
	if !profiled {
		return nil
	}
	return runner.ApplyScanPace(settings, opts, runner.ExplicitPace{
		Concurrency:        concurrencyKnob.globalChanged(),
		RateLimit:          rateLimitKnob.globalChanged(),
		MaxPerHost:         maxPerHostKnob.globalChanged(),
		MaxRequests:        opts.MaxRequests > 0,
		MaxRequestsPerHost: opts.MaxRequestsPerHost > 0,
	})
}
