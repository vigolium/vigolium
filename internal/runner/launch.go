package runner

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// LaunchParams configures a one-shot scan started from a library caller.
// The intended consumer is the olium agent's run_scan / run_extension tools —
// anything that wants to drive a scan without rebuilding the full CLI option
// matrix. Only Targets is required; the rest fall back to sensible defaults.
type LaunchParams struct {
	// Targets lists URLs / file paths the scan should ingest. Required.
	Targets []string

	// ProjectUUID scopes the scan. Empty leaves it unscoped — the same
	// behavior as `vigolium scan-url` without --project.
	ProjectUUID string

	// Modules optionally narrows the active-module set. Empty = no
	// restriction (CLI default).
	Modules []string

	// PassiveModules narrows the passive set. Empty = ["all"].
	PassiveModules []string

	// ExtensionPaths supplies extra JS extension files to load alongside
	// any built-ins. Each path is appended to ExtensionsConfig.CustomDir
	// before the runner builds its phase infra.
	ExtensionPaths []string

	// ExtensionsOnly skips all built-in Go modules; runs only JS
	// extensions. Used by run_extension when the agent wants its supplied
	// script to run in isolation.
	ExtensionsOnly bool

	// ScanningStrategy selects a named strategy ("lite", "balanced",
	// "deep"). Empty inherits the settings default.
	ScanningStrategy string

	// EnableDiscovery turns on the discovery phase. Default false — most
	// agent invocations want a targeted dynamic-assessment-only scan.
	EnableDiscovery bool

	// EnableSpidering turns on browser-based spidering. Default false.
	EnableSpidering bool

	// ConfigPath overrides the path to vigolium-configs.yaml. Empty =
	// default search order.
	ConfigPath string

	// Repository is the DB handle used for persistence and final result
	// readback. Nil is allowed — the scan still runs but results aren't
	// persisted and LaunchResult fields will be zero.
	Repository *database.Repository

	// Concurrency overrides the worker count. 0 = settings default.
	Concurrency int

	// OnlyPhase, when non-empty, isolates one or more phases via the same
	// comma-separated syntax `vigolium scan --only` accepts (e.g.
	// "discovery", "dynamic-assessment", "discovery,dynamic-assessment").
	// Phase aliases (deparos, dast, ext, etc.) are accepted and normalized.
	// Empty preserves the default phase plan derived from settings.
	OnlyPhase string

	// SkipPhases disables one or more phases while keeping the rest of the
	// plan intact. Mutually exclusive with OnlyPhase. Same alias normalization.
	SkipPhases []string

	// SkipIngestion skips the discovery ingestion phase. When you've already
	// got records in the project and just want to (re)run dynamic-assessment
	// against them, set this true and the runner will scan existing records
	// instead of crawling new ones.
	SkipIngestion bool
}

// LaunchResult summarizes a completed scan. Populated from the Scan DB row
// after RunNativeScan returns. When Repository is nil at launch time, only
// ScanUUID and DurationMs are populated.
type LaunchResult struct {
	ScanUUID      string
	Status        string
	FindingCount  int64
	TotalRequests int64
	Critical      int64
	High          int64
	Medium        int64
	Low           int64
	Info          int64
	Suspect       int64
	DurationMs    int64
}

// LaunchScan runs a single scan synchronously. Blocks until RunNativeScan
// returns (success, failure, or ctx cancellation).
//
// The scan UUID is generated up-front so callers can correlate post-hoc
// even if the run errors before any work is recorded — the UUID is real
// and queryable from the moment LaunchScan is invoked.
func LaunchScan(ctx context.Context, params LaunchParams) (*LaunchResult, error) {
	if len(params.Targets) == 0 {
		return nil, fmt.Errorf("LaunchScan: at least one target is required")
	}

	settings, err := loadLaunchSettings(params.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("LaunchScan: load settings: %w", err)
	}
	if err := applyExtensionOverrides(settings, params.ExtensionPaths); err != nil {
		return nil, fmt.Errorf("LaunchScan: extensions: %w", err)
	}

	opts := buildLaunchOptions(params)

	if opts.OnlyPhase != "" || len(opts.SkipPhases) > 0 {
		if err := ApplyNativePhaseSelection(opts, func() {
			settings.DynamicAssessment.Extensions.Enabled = true
		}); err != nil {
			return nil, fmt.Errorf("LaunchScan: %w", err)
		}
	}

	r, err := New(opts)
	if err != nil {
		return nil, fmt.Errorf("LaunchScan: build runner: %w", err)
	}
	defer r.Close()

	r.SetSettings(settings)
	if params.Repository != nil {
		r.SetRepository(params.Repository)
	}

	// Bridge ctx cancellation to the runner. The runner exposes Close()
	// (which cancels its internal context) but no public Cancel — closing
	// in a goroutine guarded by ctx.Done is the cleanest hook today.
	// `defer close(stop)` (rather than an explicit close at the end) so
	// the goroutine drains even if RunNativeScan panics.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-stop:
		}
	}()

	started := time.Now()
	runErr := r.RunNativeScan()
	elapsed := time.Since(started)

	res := &LaunchResult{
		ScanUUID:   opts.ScanUUID,
		DurationMs: elapsed.Milliseconds(),
	}

	if params.Repository != nil {
		// CompleteScan runs in a defer inside RunNativeScan so by the time
		// we get here the scan row should reflect final state. A read
		// failure isn't fatal — surface what we have.
		if scan, getErr := params.Repository.GetScanByUUID(ctx, opts.ScanUUID); getErr == nil && scan != nil {
			res.Status = scan.Status
			res.FindingCount = scan.TotalFindings
			res.TotalRequests = scan.TotalRequests
			res.Critical = scan.CriticalCount
			res.High = scan.HighCount
			res.Medium = scan.MediumCount
			res.Low = scan.LowCount
			res.Info = scan.InfoCount
			res.Suspect = scan.SuspectCount
		}
	}

	return res, runErr
}

// loadLaunchSettings resolves the settings the runner will use. We prefer
// the same precedence as the CLI: explicit ConfigPath, else default search.
func loadLaunchSettings(configPath string) (*config.Settings, error) {
	settings, err := config.LoadSettings(configPath)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		// LoadSettings returns defaults when no file exists — but be
		// defensive.
		settings = &config.Settings{}
	}
	return settings, nil
}

// applyExtensionOverrides folds caller-supplied script paths into the
// ExtensionsConfig and force-enables the JS extension subsystem when any
// were provided. Existing CustomDir entries are preserved.
func applyExtensionOverrides(settings *config.Settings, paths []string) error {
	if settings == nil || len(paths) == 0 {
		return nil
	}
	abs := make([]string, 0, len(paths))
	for _, p := range paths {
		ap, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", p, err)
		}
		abs = append(abs, ap)
	}
	ext := &settings.DynamicAssessment.Extensions
	ext.Enabled = true
	ext.CustomDir = append(ext.CustomDir, abs...)
	return nil
}

// buildLaunchOptions constructs the *types.Options the runner expects from
// the flat LaunchParams. Sets a fresh ScanUUID so callers always have a
// stable correlation key.
func buildLaunchOptions(params LaunchParams) *types.Options {
	opts := types.DefaultOptions()
	opts.Targets = params.Targets
	opts.ProjectUUID = params.ProjectUUID
	opts.ConfigPath = params.ConfigPath
	opts.Modules = params.Modules
	if len(params.PassiveModules) > 0 {
		opts.PassiveModules = params.PassiveModules
	}
	opts.ExtensionsOnly = params.ExtensionsOnly
	opts.DiscoverEnabled = params.EnableDiscovery
	opts.SpideringEnabled = params.EnableSpidering
	opts.ScanningStrategy = params.ScanningStrategy
	opts.OnlyPhase = params.OnlyPhase
	if len(params.SkipPhases) > 0 {
		opts.SkipPhases = append(opts.SkipPhases, params.SkipPhases...)
	}
	if params.SkipIngestion {
		opts.SkipIngestion = true
	}
	if params.Concurrency > 0 {
		opts.Concurrency = params.Concurrency
		opts.ConcurrencyExplicitlySet = true
	}

	// Quiet by default — the agent reads results from the LaunchResult
	// struct, not from stderr.
	opts.Silent = true
	opts.ScanConfigPrinted = true

	opts.ScanUUID = uuid.New().String()
	return opts
}
