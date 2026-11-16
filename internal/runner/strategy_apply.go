package runner

import (
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/types"
)

// Scan-options resolution: the one place a scan request (CLI flags, a REST
// body, an agent's LaunchParams) turns into Options + Settings.
//
// Every entry point calls these functions, in this order:
//
//  1. ApplyIntensityAndProfile   intensity → profile name; load + overlay the profile
//  2. ApplyScanSettingOverrides  request values that live in Settings (oast-url,
//     scope origin, scanning max duration) — after the profile, so a typed value
//     outranks the profile's
//  3. ApplyScanStrategy          explicit rate limit → strategy phases → the
//     strategy's pace ceiling (NarrowPace) → heuristics level
//  4. ApplyNativePhaseSelection  --only / --skip (caller-owned, it needs the
//     extension setter)
//  5. per-phase pace qualifiers  (CLI only: --rate-limit known-issue-scan=20)
//  6. ApplyScanPace              validate scanning_pace, fold its common values
//     into Options for knobs the caller did not set, resolve per-phase durations
//
// The functions are pure with respect to the outside world: they read a
// profile file when one is named and nothing else. No output file, no wordlist
// materialization, no network — so a dry run (`scan --dry-run`, a REST
// dry_run, the scan.plan event) can run the same resolution a real scan does.
//
// They existed as three diverging copies (scan.go, handlers_scan.go and
// launch.go). The REST copy never applied the strategy pace ceiling, so
// `strategy: lite` over the API ran at full speed, and launch.go ignored the
// strategy entirely, so the agent's run_scan with `lite` was not lite.

// ErrUnknownStrategy is returned (wrapped) when a strategy name matches none of
// the configured strategies. The CLI maps it to a usage error, REST to a 400.
var ErrUnknownStrategy = errors.New("unknown scanning strategy")

// ExplicitPace says which pace knobs the caller set itself. Those are never
// narrowed by a strategy ceiling and never replaced by scanning_pace values:
// an explicit --concurrency 40 alongside --strategy lite is an operator
// overruling the preset, which is the point of having both.
type ExplicitPace struct {
	Concurrency bool
	RateLimit   bool
	MaxPerHost  bool
	// ExternalHarvest keeps the caller's opts.ExternalHarvestEnabled instead of
	// the strategy's external_harvesting (`--intensity balanced --external-harvest`).
	ExternalHarvest bool
	// DiscoverMaxDuration / SpideringMaxDuration keep the caller's per-phase
	// duration instead of the scanning_pace-resolved one.
	DiscoverMaxDuration  bool
	SpideringMaxDuration bool
	// MaxRequests / MaxRequestsPerHost keep the caller's request budget instead
	// of scanning_pace.max_requests / max_requests_per_host.
	MaxRequests        bool
	MaxRequestsPerHost bool
}

// StrategyRequest is the strategy half of a scan request.
type StrategyRequest struct {
	// Name selects the strategy; "" falls back to scanning_strategy.default_strategy.
	Name string
	// HeuristicsCheck is a request-level heuristics level; "" falls back to
	// scanning_strategy.heuristics_check, then "basic".
	HeuristicsCheck string
	// SkipHeuristics forces the heuristics level to "none" (--skip-heuristics).
	SkipHeuristics bool
	Explicit       ExplicitPace
}

// ResolvedStrategy is what ApplyScanStrategy settled on.
type ResolvedStrategy struct {
	// Name is the strategy that applied; "" when neither the request nor the
	// settings named one (no strategy, phases left as the caller set them).
	Name   string
	Phases config.StrategyPhases
}

// ProfileRequest is the intensity/profile half of a scan request.
type ProfileRequest struct {
	// Intensity is quick|balanced|deep; "" means not requested.
	Intensity string
	// Profile is an explicit scanning profile name or path. It wins over the
	// profile the intensity maps to; "" falls back to the intensity's profile,
	// then to scanning_strategy.scanning_profile.
	Profile string
}

// ResolvedPace is the invocation-wide pace a resolved scan will run with. REST
// returns it on the scan-accepted response so a caller sees what will run.
type ResolvedPace struct {
	Strategy    string `json:"strategy"`
	Concurrency int    `json:"concurrency"`
	RateLimit   int    `json:"rate_limit"`
	MaxPerHost  int    `json:"max_per_host"`
}

// ResolvedPaceOf reports the pace opts carries after ApplyScanPace.
func ResolvedPaceOf(strategy string, opts *types.Options) ResolvedPace {
	return ResolvedPace{
		Strategy:    strategy,
		Concurrency: opts.Concurrency,
		RateLimit:   opts.RateLimit,
		MaxPerHost:  opts.MaxPerHost,
	}
}

// ApplyIntensityAndProfile resolves the intensity to its scanning profile, picks
// the profile (explicit > intensity's > scanning_strategy.scanning_profile),
// loads it and overlays it onto settings. It sets opts.Intensity and
// opts.ScanningProfile, and returns the resolved profile path ("" when no
// profile applied).
//
// An invalid intensity or a profile that cannot be loaded or applied is an
// error on every entry point. The REST records path used to swallow both and
// scan without the profile the caller asked for.
func ApplyIntensityAndProfile(settings *config.Settings, opts *types.Options, req ProfileRequest) (string, error) {
	profileName := req.Profile
	if req.Intensity != "" {
		intensity, err := agenttypes.ValidateIntensity(req.Intensity)
		if err != nil {
			return "", err
		}
		opts.Intensity = string(intensity)
		if profileName == "" {
			profileName = agenttypes.NativeScanIntensityProfiles[intensity]
		}
	}
	if profileName == "" {
		profileName = settings.ScanningStrategy.ScanningProfile
	}
	if profileName == "" {
		return "", nil
	}
	profilePath := settings.ScanningStrategy.ResolveProfilePath(profileName)
	profile, err := config.LoadProfileWithBuiltin(profilePath, profileName)
	if err != nil {
		return "", fmt.Errorf("failed to load scanning profile %q: %w", profileName, err)
	}
	if err := config.ApplyProfile(settings, profile); err != nil {
		return "", fmt.Errorf("failed to apply scanning profile %q: %w", profileName, err)
	}
	opts.ScanningProfile = profileName
	return profilePath, nil
}

// ApplyScanSettingOverrides copies request values that are read from Settings
// rather than Options. Run it after ApplyIntensityAndProfile: a profile may
// carry scope and scanning_pace sections, and a value the caller typed outranks
// the profile's.
//
// opts.ScanMaxDuration plays two roles: it seeds the per-phase duration base
// (each phase scales scanning_pace.max_duration by its duration_factor) and
// caps the whole scan's wall clock, so the factors distribute time within the
// budget rather than stacking past it.
func ApplyScanSettingOverrides(settings *config.Settings, opts *types.Options) {
	if opts.OastURL != "" {
		settings.OAST.OastURL = opts.OastURL
	}
	if opts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = opts.ScopeOriginMode
	}
	if opts.ScanMaxDuration > 0 {
		settings.ScanningPace.MaxDuration = opts.ScanMaxDuration.String()
	}
}

// ApplyScanStrategy is the one place a strategy turns into Options and pace.
//
// Order: an explicit rate limit is written into scanning_pace first (so
// known-issue-scan honours it and the ceiling below leaves it alone) → the
// strategy's phases → the external-harvest override → the strategy's pace
// ceiling, narrowing only knobs the caller did not set → the heuristics level.
//
// Phase selection (--only/--skip) is NOT applied here: callers run
// ApplyNativePhaseSelection next, so a selection overrides the strategy.
func ApplyScanStrategy(settings *config.Settings, opts *types.Options, req StrategyRequest) (ResolvedStrategy, error) {
	pace := &settings.ScanningPace

	// A typed rate limit outranks the profile's scanning_pace.rate_limit, which
	// is why this runs after ApplyIntensityAndProfile and not before it.
	if req.Explicit.RateLimit {
		pace.RateLimit = opts.RateLimit
	}

	name := req.Name
	if name == "" {
		name = settings.ScanningStrategy.DefaultStrategy
	}
	var resolved ResolvedStrategy
	if name != "" {
		phases, ok := settings.ScanningStrategy.GetStrategy(name)
		if !ok {
			return ResolvedStrategy{}, fmt.Errorf("%w %q; valid names: %v", ErrUnknownStrategy, name, settings.ScanningStrategy.StrategyNames())
		}
		resolved = ResolvedStrategy{Name: name, Phases: phases}
		opts.ScanningStrategy = name
		opts.DiscoverEnabled = phases.Discovery
		opts.SpideringEnabled = phases.Spidering
		opts.KnownIssueScanEnabled = phases.KnownIssueScan
		if !phases.DynamicAssessment {
			opts.SkipDynamicAssessment = true
		}
		if !req.Explicit.ExternalHarvest {
			opts.ExternalHarvestEnabled = phases.ExternalHarvesting
		}
		// Provenance for the scan plan's disabled_by.
		noteStrategyPhase(opts, PhaseDiscovery, phases.Discovery)
		noteStrategyPhase(opts, PhaseSpidering, phases.Spidering)
		noteStrategyPhase(opts, PhaseKnownIssueScan, phases.KnownIssueScan)
		noteStrategyPhase(opts, PhaseDynamicAssessment, phases.DynamicAssessment)
		if !req.Explicit.ExternalHarvest {
			noteStrategyPhase(opts, PhaseExternalHarvest, phases.ExternalHarvesting)
		}
		// A strategy is a narrowing request, so its ceiling applies before the
		// per-phase overrides and before pace validation. Without it `lite`
		// selected fewer modules and opened exactly as wide as `balanced`.
		if ceiling := phases.Pace; ceiling != (config.StrategyPace{}) {
			if !req.Explicit.Concurrency {
				pace.Concurrency = config.NarrowPace(pace.Concurrency, ceiling.Concurrency)
				opts.Concurrency = pace.Concurrency
				if ceiling.Concurrency > 0 && (opts.ConcurrencyCeiling == 0 || ceiling.Concurrency < opts.ConcurrencyCeiling) {
					opts.ConcurrencyCeiling = ceiling.Concurrency
				}
			}
			if !req.Explicit.RateLimit {
				pace.RateLimit = config.NarrowPace(pace.RateLimit, ceiling.RateLimit)
				opts.RateLimit = pace.RateLimit
			}
			if !req.Explicit.MaxPerHost {
				pace.MaxPerHost = config.NarrowPace(pace.MaxPerHost, ceiling.MaxPerHost)
				opts.MaxPerHost = pace.MaxPerHost
			}
		}
	}

	// Precedence: SkipHeuristics > request level > config > "basic".
	opts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		opts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if req.HeuristicsCheck != "" {
		opts.HeuristicsCheck = req.HeuristicsCheck
	}
	if req.SkipHeuristics {
		opts.HeuristicsCheck = "none"
	}
	if opts.HeuristicsCheck == "none" {
		opts.NotePhaseDisabled(string(PhaseHeuristicsCheck), "heuristics")
	}
	return resolved, nil
}

// noteStrategyPhase records a phase the strategy turned off, or clears a stale
// record for one it turned on.
func noteStrategyPhase(opts *types.Options, phase NativePhase, enabled bool) {
	if enabled {
		opts.NotePhaseEnabled(string(phase))
		return
	}
	opts.NotePhaseDisabled(string(phase), "strategy")
}

// ApplyScanPace validates scanning_pace, folds its common values into opts for
// every knob the caller did not set explicitly (scanning_pace is the lowest
// rung above the built-in defaults), and resolves the discovery and spidering
// max durations from max_duration × duration_factor.
//
// Run it last — after the strategy ceiling, the phase selection and any
// per-phase qualifiers — so the values it folds are the final ones.
//
// It also records the caller's explicit knobs on opts, which is where the
// runner reads them (host limiter, per-phase concurrency, discovery rate);
// every entry point runs it after ApplyScanStrategy with the same ExplicitPace.
func ApplyScanPace(settings *config.Settings, opts *types.Options, explicit ExplicitPace) error {
	opts.ConcurrencyExplicitlySet = explicit.Concurrency
	opts.RateLimitExplicitlySet = explicit.RateLimit
	opts.MaxPerHostExplicitlySet = explicit.MaxPerHost
	pace := &settings.ScanningPace
	if err := pace.Validate(); err != nil {
		return fmt.Errorf("invalid scanning_pace configuration: %w", err)
	}
	// VIGOLIUM_RATE_CEILING: clamp the config's dials before they fold into
	// Options, and Options after, so neither source can exceed it.
	pace.CeilPace()
	defer config.CeilOptionsPace(opts)
	if !explicit.Concurrency && pace.Concurrency > 0 {
		opts.Concurrency = pace.Concurrency
	}
	if !explicit.MaxPerHost && pace.MaxPerHost > 0 {
		opts.MaxPerHost = pace.MaxPerHost
	}
	// The rate limit follows the same rung as its two siblings: a config file
	// that set scanning_pace.rate_limit used to pace known-issue-scan while the
	// native scan ran at the flag default.
	if !explicit.RateLimit && pace.RateLimit > 0 {
		opts.RateLimit = pace.RateLimit
	}
	if !explicit.MaxRequests && pace.MaxRequests > 0 {
		opts.MaxRequests = pace.MaxRequests
	}
	if !explicit.MaxRequestsPerHost && pace.MaxRequestsPerHost > 0 {
		opts.MaxRequestsPerHost = pace.MaxRequestsPerHost
	}
	if d := pace.ResolvePhase(string(PhaseDiscovery)).MaxDuration; !explicit.DiscoverMaxDuration && d > 0 {
		opts.DiscoverMaxDuration = d
	}
	// The source travels with the value so SpideringBudget can tell a derived
	// budget (which gets the spidering floor) from one somebody chose.
	switch spider := pace.ResolvePhase(string(PhaseSpidering)); {
	case explicit.SpideringMaxDuration:
		opts.SpideringMaxDurationSource = SpideringSourceFlag
	case spider.MaxDuration > 0:
		opts.SpideringMaxDuration = spider.MaxDuration
		opts.SpideringMaxDurationSource = string(spider.Source)
	}
	return nil
}
