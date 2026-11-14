package server

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/types"
)

// REST scan-options resolution. Both scan-launching routes (POST /api/scans/run
// and POST /api/scan-all-records) resolve through the runner functions the CLI
// uses (runner/strategy_apply.go). The REST copy used to diverge: it skipped the
// strategy's pace ceiling (so `strategy: lite` ran at full speed), ignored
// scanning_pace concurrency/max_per_host, and the records route swallowed
// profile errors and scanned without the profile the caller named.

// applyRequestPace copies the pace values a request typed into opts. Zero means
// unset: the server's worker default stands in for concurrency until
// ApplyScanPace folds scanning_pace over every knob the request left unset.
func applyRequestPace(opts *types.Options, serverConcurrency, concurrency, rateLimit, maxPerHost int) {
	opts.Concurrency = serverConcurrency
	if opts.Concurrency <= 0 {
		opts.Concurrency = types.DefaultConcurrency
	}
	if concurrency > 0 {
		opts.Concurrency = concurrency
	}
	if rateLimit > 0 {
		opts.RateLimit = rateLimit
	}
	if maxPerHost > 0 {
		opts.MaxPerHost = maxPerHost
	}
}

// requestExplicitPace mirrors the CLI rule that a typed value overrules the
// strategy ceiling and scanning_pace: a positive request value is explicit.
func requestExplicitPace(concurrency, rateLimit, maxPerHost int) runner.ExplicitPace {
	return runner.ExplicitPace{
		Concurrency: concurrency > 0,
		RateLimit:   rateLimit > 0,
		MaxPerHost:  maxPerHost > 0,
	}
}

// resolveRequestStrategy runs the first three resolution steps: intensity and
// profile, the settings overrides carried on opts, then the strategy.
func resolveRequestStrategy(settings *config.Settings, opts *types.Options, intensity, profile string, req runner.StrategyRequest) (runner.ResolvedStrategy, error) {
	if _, err := runner.ApplyIntensityAndProfile(settings, opts, runner.ProfileRequest{
		Intensity: intensity,
		Profile:   profile,
	}); err != nil {
		return runner.ResolvedStrategy{}, err
	}
	runner.ApplyScanSettingOverrides(settings, opts)
	runner.ApplyDefaultScanBudget(settings, opts)
	return runner.ApplyScanStrategy(settings, opts, req)
}

// newScanResolved reports the pace a resolved scan will run with.
func newScanResolved(strategy string, opts *types.Options) *ScanResolved {
	p := runner.ResolvedPaceOf(strategy, opts)
	return &ScanResolved{
		Strategy:    p.Strategy,
		Concurrency: p.Concurrency,
		RateLimit:   p.RateLimit,
		MaxPerHost:  p.MaxPerHost,
	}
}

// resolveScanAllRecordsOptions resolves a POST /api/scan-all-records body. The
// route re-scans stored records, so it is dynamic-assessment only whatever the
// strategy says: the strategy contributes its pace ceiling, the phases stay off.
// Heuristics stay off unless the request names a level, as before.
//
// settings is mutated and must be the request's own clone.
func resolveScanAllRecordsOptions(settings *config.Settings, serverConcurrency int, req ScanAllRecordsRequest, projectUUID string) (*types.Options, runner.ResolvedStrategy, error) {
	opts := types.DefaultOptions()
	applyAPIModuleSelection(opts, req.Modules, req.ModuleTags)
	opts.ProjectUUID = projectUUID
	applyRequestPace(opts, serverConcurrency, req.Concurrency, req.RateLimit, req.MaxPerHost)

	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			return nil, runner.ResolvedStrategy{}, fmt.Errorf("invalid timeout: %w", err)
		}
		opts.Timeout = d
	}
	if req.ScanningMaxDuration != "" {
		d, err := time.ParseDuration(req.ScanningMaxDuration)
		if err != nil {
			return nil, runner.ResolvedStrategy{}, fmt.Errorf("invalid scanning_max_duration: %w", err)
		}
		opts.ScanMaxDuration = d
	}
	opts.MaxRequests = req.MaxRequests
	opts.MaxRequestsPerHost = req.MaxRequestsPerHost
	if len(req.Headers) > 0 {
		headers := make([]string, 0, len(req.Headers))
		for k, v := range req.Headers {
			headers = append(headers, k+": "+v)
		}
		opts.Headers = headers
	}

	explicit := requestExplicitPace(req.Concurrency, req.RateLimit, req.MaxPerHost)
	explicit.MaxRequests = req.MaxRequests > 0
	explicit.MaxRequestsPerHost = req.MaxRequestsPerHost > 0
	strategy, err := resolveRequestStrategy(settings, opts, req.Intensity, req.ScanningProfile, runner.StrategyRequest{
		HeuristicsCheck: req.HeuristicsCheck,
		SkipHeuristics:  req.HeuristicsCheck == "",
		Explicit:        explicit,
	})
	if err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	opts.SkipIngestion = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SpideringEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = false

	if err := runner.ApplyScanPace(settings, opts, explicit); err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	return opts, strategy, nil
}
