package knownissuescan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Config holds configuration for a known-issue scan.
type Config struct {
	Targets      []string      // scheme://host:port URLs to scan
	Concurrency  int           // nuclei host concurrency (default: 5)
	RateLimit    int           // requests/sec (default: 150)
	Tags         []string      // template tags to include (empty = all)
	ExcludeTags  []string      // template tags to exclude
	Severities   []string      // filter by severity (empty = all)
	TemplatesDir string        // custom templates directory
	Timeout      time.Duration // max known-issue scan duration (default: 30m)
	// RequestTimeout bounds a single nuclei request (default: 10s). It also caps
	// how long an in-flight request can keep the abandoned scan goroutine alive
	// after the phase deadline fires (see Run's deadline path).
	RequestTimeout time.Duration
	// Retries is the nuclei per-request retry count (default: 1). Fewer retries
	// shrink the post-deadline drain tail.
	Retries int
	Headers []string // custom headers
	// SeverityOverrides remaps a finding's severity by nuclei template ID
	// (matched case-insensitively). Applied to each match before OnResult and
	// persistence, so output, severity counts, and the stored finding all agree.
	SeverityOverrides map[string]string
	ProxyURL          string                    // proxy URL
	OnResult          func(*output.ResultEvent) // callback per finding
	Repository        *database.Repository      // for saving findings
	ScanUUID          string
	ProjectUUID       string
}

// Run executes the known-issue scan using the nuclei Go library.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("knownissuescan: no targets provided")
	}

	// Apply defaults
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 1
	}

	// Ensure nuclei templates are available before attempting to scan
	if err := ensureTemplates(cfg.TemplatesDir); err != nil {
		return err
	}

	// Create a properly initialized logger for nuclei to avoid nil pointer
	// panics from the bare default logger in nuclei's DefaultOptions().
	scanLogger := &gologger.Logger{}
	scanLogger.SetFormatter(formatter.NewCLI(false))
	scanLogger.SetWriter(writer.NewCLI())
	// Always silence nuclei's gologger — its [WRN]/[INF]/[VER] messages are
	// noisy and not actionable. Vigolium uses its own zap logger for output.
	scanLogger.SetMaxLevel(levels.LevelSilent)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	// Build engine options
	opts := buildEngineOptions(ctx, cfg, scanLogger)

	// Log the active severity filter (empty = all) so the narrowing is visible in
	// both CLI and server logs, not only via the CLI-only console tip.
	loggedSeverities := cfg.Severities
	if len(loggedSeverities) == 0 {
		loggedSeverities = []string{"all"}
	}
	zap.L().Info("Starting known-issue scan",
		zap.Int("targets", len(cfg.Targets)),
		zap.Int("concurrency", cfg.Concurrency),
		zap.Int("rate_limit", cfg.RateLimit),
		zap.Strings("tags", cfg.Tags),
		zap.Strings("exclude_tags", cfg.ExcludeTags),
		zap.Strings("severities", loggedSeverities),
		zap.Duration("timeout", cfg.Timeout),
	)

	// Create nuclei engine with timeout context. NOTE: cancel() is deferred, but
	// ne.Close() is NOT — its safety depends on the exit path (see below), so it
	// is invoked explicitly per-path.
	scanCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	ne, err := nuclei.NewNucleiEngineCtx(scanCtx, opts...)
	if err != nil {
		return fmt.Errorf("knownissuescan: failed to create nuclei engine: %w", err)
	}

	// Load targets
	ne.LoadTargets(cfg.Targets, false)

	// Normalize severity-override keys to lowercase once so per-finding lookups
	// are a cheap case-insensitive map hit (nuclei template IDs are lowercase by
	// convention, but operators may not type them that way in config).
	severityOverrides := normalizeSeverityOverrides(cfg.SeverityOverrides)

	// done flips once Run has moved past the deadline. The callback checks it (and
	// scanCtx.Err()) so the abandoned nuclei goroutine stops emitting findings /
	// DB writes after we've returned. findingCount is atomic because nuclei fires
	// the callback from worker goroutines while we read it from the main goroutine.
	var done atomic.Bool
	var findingCount atomic.Int64

	callback := func(event *nucleiOutput.ResultEvent) {
		// Stop persisting once the phase has moved past its deadline. This prevents
		// the abandoned nuclei goroutine from writing findings (and racing a closed
		// scan row) after Run has returned.
		if done.Load() || scanCtx.Err() != nil {
			return
		}
		// Only process genuine matches — nuclei fires the callback for all
		// template evaluations, including non-matches.
		if !event.MatcherStatus {
			return
		}

		result := convertResult(event)
		result.ModuleType = database.ModuleTypeKnownIssueScan
		result.FindingSource = database.FindingSourceKnownIssueScan
		// Apply any operator-configured severity remap before OnResult and
		// persistence so output, severity counts, and the stored finding agree.
		if override, ok := severityOverrides[strings.ToLower(result.ModuleID)]; ok {
			result.Info.Severity = override
		}
		findingCount.Add(1)

		// Invoke user callback
		if cfg.OnResult != nil {
			cfg.OnResult(result)
		}

		// Persist to database. Use scanCtx (not the parent ctx) so a write that
		// races the deadline fails fast on a cancelled context instead of landing
		// in the finished phase's counters.
		if cfg.Repository != nil {
			var httpRecordUUIDs []string
			if result.Request != "" {
				fuzzedRR := httpmsg.NewHttpRequestResponse(
					httpmsg.NewHttpRequest([]byte(result.Request)),
					httpmsg.NewHttpResponse([]byte(result.Response)),
				)
				recordUUID, recErr := cfg.Repository.SaveRecord(scanCtx, fuzzedRR, "spa", cfg.ProjectUUID)
				if recErr != nil {
					zap.L().Debug("KnownIssueScan: failed to save http record", zap.Error(recErr))
				} else {
					httpRecordUUIDs = []string{recordUUID}
				}
			}
			if saveErr := cfg.Repository.SaveFinding(scanCtx, result, httpRecordUUIDs, cfg.ScanUUID, cfg.ProjectUUID); saveErr != nil {
				zap.L().Debug("KnownIssueScan: failed to save finding", zap.Error(saveErr))
			}
		}
	}

	// nuclei's ExecuteCallbackWithCtx blocks on its internal in-flight drain even
	// after scanCtx is cancelled (it does <-wait(&wg) on ctx.Done()). Run it in our
	// own goroutine and enforce cfg.Timeout / parent-cancel as a HARD wall-clock
	// bound: return at the deadline instead of waiting for the drain.
	var scanErr error
	deadlineErr := runScanWithDeadline(scanCtx,
		func() error { return ne.ExecuteCallbackWithCtx(scanCtx, callback) },
		// onComplete: scan returned within budget — its goroutine is gone, so
		// Close() is safe inline here. The scan's own error is captured for
		// classification below.
		func(e error) { scanErr = e; ne.Close() },
		// onAbandon: detached cleanup. Runs only after the abandoned scan goroutine
		// finally drains, so Close() never races a live scan. May never run if a
		// no-deadline protocol read hangs (inherent nuclei limit) — but that no
		// longer blocks the caller.
		func() { ne.Close() },
	)

	if deadlineErr != nil {
		// Deadline (or parent cancel) fired before the scan finished. The phase
		// caller classifies this as a curtailment via ctx.Err().
		done.Store(true)
		zap.L().Warn("Known-issue scan curtailed at deadline; nuclei resource cleanup deferred to background",
			zap.Int64("findings", findingCount.Load()),
			zap.Error(deadlineErr))
		return deadlineErr
	}
	if scanErr != nil {
		// A clean in-budget curtailment (nuclei drained before its own deadline
		// returned) is a curtailment, not a failure — surface it as the ctx error.
		if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
			zap.L().Info("Known-issue scan stopped at deadline", zap.Int64("findings", findingCount.Load()))
			return scanErr
		}
		return fmt.Errorf("knownissuescan: execution failed: %w", scanErr)
	}

	zap.L().Info("Known-issue scan completed", zap.Int64("findings", findingCount.Load()))
	return nil
}

// runScanWithDeadline runs scan() in a goroutine and returns as soon as either
// the scan finishes OR ctx is done — it does NOT block on the scan's drain when
// ctx fires first. On the completion path it calls onComplete(scanErr) inline
// (Close is safe there) and returns nil. On the deadline path it returns
// ctx.Err() immediately and runs onAbandon in a detached goroutine after scan()
// eventually returns, so resource cleanup never races a still-running scan.
func runScanWithDeadline(ctx context.Context, scan func() error, onComplete func(error), onAbandon func()) error {
	scanErr := make(chan error, 1) // buffered: the scan goroutine's send never blocks
	go func() { scanErr <- scan() }()
	select {
	case err := <-scanErr:
		onComplete(err)
		return nil
	case <-ctx.Done():
		go func() { <-scanErr; onAbandon() }()
		return ctx.Err()
	}
}

// buildEngineOptions constructs nuclei SDK options from known-issue scan config.
func buildEngineOptions(ctx context.Context, cfg Config, logger *gologger.Logger) []nuclei.NucleiSDKOptions {
	var opts []nuclei.NucleiSDKOptions

	// Template filters
	filters := nuclei.TemplateFilters{
		Tags:        cfg.Tags,
		ExcludeTags: cfg.ExcludeTags,
		// KnownIssueScan runs against web targets (HTTP URLs), so non-web
		// protocol templates are irrelevant here — and the raw service probes
		// are an active liability: nuclei's SMB JS lib (a "javascript" protocol
		// template, smb.ListShares) opens a go-smb2 session whose receiver
		// goroutine reads with NO deadline, so against an open-but-non-SMB port
		// the negotiate read hangs forever and the goroutine leaks (the engine's
		// Close() can't reap it). One scan per process hides this, but a
		// long-lived process running many scans accumulates the leaks until it
		// stalls. Excluding the "tcp" (network) and "javascript" protocol types
		// removes the leak at the source and speeds up the phase. http,
		// headless, dns, ssl, websocket, etc. still run.
		ExcludeProtocolTypes: "tcp,javascript",
	}
	if len(cfg.Severities) > 0 {
		filters.Severity = strings.Join(cfg.Severities, ",")
	}
	opts = append(opts, nuclei.WithTemplateFilters(filters))

	// Custom templates directory
	if cfg.TemplatesDir != "" {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{cfg.TemplatesDir},
		}))
	}

	// Rate limit
	opts = append(opts, nuclei.WithGlobalRateLimitCtx(ctx, cfg.RateLimit, time.Second))

	// Per-request network timeout and retry budget. nuclei cancellation is
	// cooperative: when the phase deadline fires, in-flight requests run to their
	// per-request timeout before the abandoned scan goroutine can drain. An explicit
	// short Timeout (seconds) and low Retries bound that drain tail. NOTE: this
	// cannot bound a genuinely no-deadline read (the SMB/JS leak class excluded via
	// ExcludeProtocolTypes below) — for those the detached cleanup goroutine in Run
	// may never finish, but it no longer blocks the caller.
	reqTimeoutSecs := int(cfg.RequestTimeout / time.Second)
	if reqTimeoutSecs < 1 {
		reqTimeoutSecs = 1
	}
	opts = append(opts, nuclei.WithNetworkConfig(nuclei.NetworkConfig{
		Timeout:      reqTimeoutSecs,
		Retries:      cfg.Retries,
		MaxHostError: 30, // skip persistently-failing hosts fast (nuclei raises this to concurrency if lower)
	}))

	// Concurrency
	opts = append(opts, nuclei.WithConcurrency(nuclei.Concurrency{
		TemplateConcurrency:           10,
		HostConcurrency:               cfg.Concurrency,
		HeadlessHostConcurrency:       1,
		HeadlessTemplateConcurrency:   1,
		JavascriptTemplateConcurrency: 1,
		TemplatePayloadConcurrency:    25,
		ProbeConcurrency:              50,
	}))

	// Proxy
	if cfg.ProxyURL != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.ProxyURL}, false))
	}

	// Custom headers
	if len(cfg.Headers) > 0 {
		opts = append(opts, nuclei.WithHeaders(cfg.Headers))
	}

	// Always run nuclei in silent mode — its internal logging is noisy and
	// not useful. Vigolium's own zap logger handles verbose/debug output.
	opts = append(opts, nuclei.WithVerbosity(nuclei.VerbosityOptions{
		Verbose: false,
		Silent:  true,
	}))

	// Disable update checks in library mode
	opts = append(opts, nuclei.DisableUpdateCheck())

	// Pass our properly initialized logger to avoid nil pointer panics
	// from nuclei's bare default logger.
	opts = append(opts, nuclei.WithLogger(logger))

	return opts
}

// convertResult maps a nuclei output.ResultEvent to a vigolium ResultEvent.
func convertResult(nr *nucleiOutput.ResultEvent) *output.ResultEvent {
	result := &output.ResultEvent{
		ModuleID: nr.TemplateID,
		Info: output.Info{
			Name:        nr.Info.Name,
			Description: nr.Info.Description,
			Severity:    parseSeverity(nr.Info.SeverityHolder.Severity.String()),
			Confidence:  severity.Firm,
		},
		Type:             nr.Type,
		Host:             nr.Host,
		Matched:          nr.Matched,
		URL:              nr.URL,
		IP:               nr.IP,
		Request:          nr.Request,
		Response:         nr.Response,
		ExtractedResults: nr.ExtractedResults,
		MatcherStatus:    nr.MatcherStatus,
		Timestamp:        time.Now(),
		ModuleShort:      nr.Info.Description,
	}

	// Map tags
	if !nr.Info.Tags.IsEmpty() {
		result.Info.Tags = nr.Info.Tags.ToSlice()
	}

	// Map references
	if nr.Info.Reference != nil && !nr.Info.Reference.IsEmpty() {
		result.Info.Reference = nr.Info.Reference.ToSlice()
	}

	// Fallback URL
	if result.URL == "" {
		result.URL = nr.Host
	}

	return result
}

// ensureTemplates checks that nuclei templates are available and attempts to
// download them if missing. When Vigolium embeds nuclei as a library, the
// automatic template download that the nuclei CLI performs does not run, so
// fresh environments (Docker, VPS) may not have templates installed.
func ensureTemplates(customDir string) error {
	dir := customDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("knownissuescan: cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, "nuclei-templates")
	}

	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return nil
	}

	zap.L().Info("KnownIssueScan: nuclei templates not found, attempting to download",
		zap.String("path", dir))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("knownissuescan: nuclei templates not found at %s and auto-download failed: %s\n"+
			"Install manually: git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git %s",
			dir, strings.TrimSpace(string(out)), dir)
	}

	zap.L().Info("KnownIssueScan: nuclei templates downloaded successfully", zap.String("path", dir))
	return nil
}

// normalizeSeverityOverrides parses the operator's template-ID→severity remap
// once, lowercasing keys for case-insensitive matching and dropping entries whose
// target severity is unparseable. Returns nil when there is nothing to apply.
func normalizeSeverityOverrides(in map[string]string) map[string]severity.Severity {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]severity.Severity, len(in))
	for tmpl, sev := range in {
		if parsed := parseSeverity(sev); parsed != severity.Undefined {
			out[strings.ToLower(strings.TrimSpace(tmpl))] = parsed
		}
	}
	return out
}

// parseSeverity maps a nuclei severity string to vigolium severity.
func parseSeverity(s string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "info":
		return severity.Info
	default:
		return severity.Undefined
	}
}
