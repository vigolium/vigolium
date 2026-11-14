package knownissuescan

import (
	"context"
	"errors"
	"fmt"
	"os"
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

	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/nucleitemplates"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Config holds configuration for a known-issue scan.
// Unattended defaults for the two pace knobs. Named rather than inline so the
// value the phase actually opens at, the value documented on --rate-limit, and
// the value reported in the scan.started event cannot drift apart.
const (
	defaultHostConcurrency = 10
	defaultRateLimit       = 20
)

type Config struct {
	Targets      []string // scheme://host:port URLs to scan
	Concurrency  int      // nuclei host concurrency (default: 5)
	RateLimit    int      // requests/sec (default: 150)
	Tags         []string // template tags to include (empty = all)
	ExcludeTags  []string // template tags to exclude
	Severities   []string // filter by severity (empty = all)
	TemplatesDir string   // custom templates directory
	// Offline forbids downloading missing templates (--offline).
	Offline bool
	// TemplatesPin is the nuclei-templates release (and archive digest) a
	// missing templates directory is installed from.
	TemplatesPin nucleitemplates.Pin
	Templates    []string      // when set, the only template sources (see templateSources)
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
	// Edge connects this phase to the scan's shared pacing infrastructure. nuclei
	// runs its own HTTP stack, so without these hooks known-issue-scan is the one
	// active phase outside the per-host limiter and the WAF block notice. See
	// edge.go for what each hook buys and why a transport port is not on offer.
	Edge Edge

	// PrefixTargets are directory-prefix URLs (scheme://host/dir) beyond the
	// origins in Targets. They are scanned in a second pass that excludes the
	// templates whose requests ignore the path (RootOnlyTemplateIDs): those
	// already ran against the origin, and every prefix of a host would resend
	// the identical request.
	PrefixTargets []string

	// Requests, when set, counts every request nuclei sends (via its progress
	// hooks). The runner registers it with the request budget so nuclei's
	// traffic counts toward --max-requests (soft enforcement: the scan stops
	// once the watcher sees the limit passed).
	Requests *atomic.Int64

	// Duplicate, when set, reports whether a match repeats a finding the
	// native modules already filed for this scan. Such a match is neither
	// emitted nor stored; the callback may record the link.
	Duplicate func(*output.ResultEvent) bool
}

// Run executes the known-issue scan using the nuclei Go library.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Targets) == 0 && len(cfg.PrefixTargets) == 0 {
		return fmt.Errorf("knownissuescan: no targets provided")
	}

	// Apply defaults.
	//
	// These are the values that apply when the operator says NOTHING, and they
	// are the phase's only protection in that case: nuclei does not pace itself,
	// does not back off, and until the Edge hooks below could not report that it
	// had been blocked. Opening an unknown target at 100 rps / 50 hosts because
	// nobody passed a flag is the fail-open direction, so the unattended defaults
	// are deliberately conservative. An operator who wants the old throughput
	// asks for it (--rate-limit / --concurrency), which is a decision on the
	// record rather than an accident of silence.
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultHostConcurrency
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = defaultRateLimit
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
	if err := EnsureTemplates(cfg, nil); err != nil {
		return err
	}

	// Edge pre-flight: probe each target host through the SHARED requester before
	// nuclei opens. Every other phase learns about a filtering edge this way; this
	// is the seam that gives known-issue-scan the same knowledge. A host that is
	// already blocking is dropped rather than scanned — pushing template traffic
	// through a wall of challenge pages produces no findings and arms the rate
	// limiter further.
	allTargets := append(append([]string(nil), cfg.Targets...), cfg.PrefixTargets...)
	if kept, blockedHosts := preflightHosts(ctx, allTargets, cfg.Edge.Probe); len(blockedHosts) > 0 {
		zap.L().Warn("KnownIssueScan: skipping hosts whose edge is already filtering scan traffic",
			zap.Strings("blocked_hosts", blockedHosts),
			zap.Int("targets_before", len(allTargets)),
			zap.Int("targets_after", len(kept)))
		keep := make(map[string]struct{}, len(kept))
		for _, t := range kept {
			keep[t] = struct{}{}
		}
		cfg.Targets = filterKept(cfg.Targets, keep)
		cfg.PrefixTargets = filterKept(cfg.PrefixTargets, keep)
		allTargets = kept
		if len(allTargets) == 0 {
			return nil
		}
	}

	// Narrow nuclei's own knobs to the per-host verdict the limiter has already
	// reached, so a CDN-fronted host makes this phase open narrow from its first
	// request instead of bursting the edge into a rate-based block.
	cfg.Concurrency, cfg.RateLimit = pacedFor(allTargets, cfg.Edge.HostLimit, cfg.Concurrency, cfg.RateLimit)

	// Create a properly initialized logger for nuclei to avoid nil pointer
	// panics from the bare default logger in nuclei's DefaultOptions().
	scanLogger := &gologger.Logger{}
	scanLogger.SetFormatter(formatter.NewCLI(false))
	scanLogger.SetWriter(writer.NewCLI())
	// Always silence nuclei's gologger — its [WRN]/[INF]/[VER] messages are
	// noisy and not actionable. Vigolium uses its own zap logger for output.
	scanLogger.SetMaxLevel(levels.LevelSilent)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	passes := planPasses(cfg)

	// Log the active severity filter (empty = all) so the narrowing is visible in
	// both CLI and server logs, not only via the CLI-only console tip.
	loggedSeverities := cfg.Severities
	if len(loggedSeverities) == 0 {
		loggedSeverities = []string{"all"}
	}
	zap.L().Info("Starting known-issue scan",
		zap.Int("targets", len(cfg.Targets)),
		zap.Int("prefix_targets", len(cfg.PrefixTargets)),
		zap.Int("passes", len(passes)),
		zap.Int("concurrency", cfg.Concurrency),
		zap.Int("rate_limit", cfg.RateLimit),
		zap.Strings("tags", cfg.Tags),
		zap.Strings("exclude_tags", cfg.ExcludeTags),
		zap.Strings("severities", loggedSeverities),
		zap.Duration("timeout", cfg.Timeout),
	)

	// One deadline for every pass. NOTE: cancel() is deferred, but ne.Close() is
	// NOT — its safety depends on the exit path (see runPass), so it is invoked
	// explicitly per-path.
	scanCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

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
		// A template that re-finds what a native module already filed (the
		// same CVE on the host, the same exposed file) is the same issue twice.
		if cfg.Duplicate != nil && cfg.Duplicate(result) {
			return
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
				recordUUID, recErr := cfg.Repository.SaveRecordWithLineage(scanCtx, fuzzedRR, database.RecordSourceFinding, cfg.ProjectUUID, database.RecordLineage{ScanUUID: cfg.ScanUUID})
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

	sentinelStarted := false
	for _, ps := range passes {
		if scanCtx.Err() != nil {
			break
		}
		ne, err := nuclei.NewNucleiEngineCtx(scanCtx, buildEngineOptions(ctx, cfg, scanLogger, ps.excludeIDs)...)
		if err != nil {
			return fmt.Errorf("knownissuescan: failed to create nuclei engine: %w", err)
		}
		// Re-probe while the scan runs: a host that starts filtering mid-phase is
		// the case the pre-flight cannot catch, and the one that silently hollows
		// out the results. Each probe rides the shared requester, so the operator
		// notice and the waf.block event fire exactly as they do in every other
		// phase.
		//
		// Started AFTER the first engine exists: NewNucleiEngineCtx can sit behind
		// a multi-minute first-run template clone, and a sentinel armed before it
		// would spend that whole window probing a target nuclei has not touched.
		if !sentinelStarted {
			sentinelStarted = true
			defer cfg.Edge.sentinel(scanCtx, allTargets, cancel)()
		}
		ne.LoadTargets(ps.targets, false)

		var scanErr error
		deadlineErr := runScanWithDeadline(scanCtx,
			func() error { return ne.ExecuteCallbackWithCtx(scanCtx, callback) },
			// onComplete: scan returned within budget — its goroutine is gone, so
			// Close() is safe inline here.
			func(e error) { scanErr = e; ne.Close() },
			// onAbandon: detached cleanup. Runs only after the abandoned scan
			// goroutine finally drains, so Close() never races a live scan.
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
			// A clean in-budget curtailment is a curtailment, not a failure —
			// surface it as the ctx error.
			if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
				zap.L().Info("Known-issue scan stopped at deadline", zap.Int64("findings", findingCount.Load()))
				return scanErr
			}
			return fmt.Errorf("knownissuescan: execution failed: %w", scanErr)
		}
	}

	zap.L().Info("Known-issue scan completed", zap.Int64("findings", findingCount.Load()))
	return nil
}

// scanPass is one nuclei engine run: a target list and the template IDs it
// excludes on top of the configured filters.
type scanPass struct {
	targets    []string
	excludeIDs []string
}

// planPasses splits the run: origins get every template; prefixes get only
// the templates whose requests depend on the path. When nothing classifies as
// origin-anchored (custom template list, unreadable dir), one pass over all
// targets is the same work without a second engine load.
func planPasses(cfg Config) []scanPass {
	if len(cfg.PrefixTargets) == 0 {
		return []scanPass{{targets: cfg.Targets}}
	}
	var rootOnly []string
	if len(cfg.Templates) == 0 {
		if dir, err := TemplatesDir(cfg.TemplatesDir); err == nil {
			rootOnly, _ = RootOnlyTemplateIDs(dir)
		}
	}
	if len(rootOnly) == 0 || len(cfg.Targets) == 0 {
		return []scanPass{{targets: append(append([]string(nil), cfg.Targets...), cfg.PrefixTargets...)}}
	}
	return []scanPass{
		{targets: cfg.Targets},
		{targets: cfg.PrefixTargets, excludeIDs: rootOnly},
	}
}

func filterKept(targets []string, keep map[string]struct{}) []string {
	out := targets[:0:0]
	for _, t := range targets {
		if _, ok := keep[t]; ok {
			out = append(out, t)
		}
	}
	return out
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
		go func() {
			if err := <-scanErr; err != nil {
				zap.L().Debug("KnownIssueScan: abandoned scan finished", zap.Error(err))
			}
			onAbandon()
		}()
		return ctx.Err()
	}
}

// buildEngineOptions constructs nuclei SDK options from known-issue scan config,
// with extra template IDs excluded (the prefix pass drops origin-anchored
// templates; nil for none).
func buildEngineOptions(ctx context.Context, cfg Config, logger *gologger.Logger, excludeIDs []string) []nuclei.NucleiSDKOptions {
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
		ExcludeIDs:           excludeIDs,
	}
	if len(cfg.Severities) > 0 {
		filters.Severity = strings.Join(cfg.Severities, ",")
	}
	opts = append(opts, nuclei.WithTemplateFilters(filters))

	// Custom templates directory, or explicit template sources
	if sources := templateSources(cfg.TemplatesDir, cfg.Templates); len(sources) > 0 {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: sources,
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

	// Count sent requests for the request budget.
	if cfg.Requests != nil {
		opts = append(opts, nuclei.UseStatsWriter(requestCounter{n: cfg.Requests}))
	}

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

// templateSources resolves what nuclei loads: the explicit templates when
// any are given (a relative entry that exists under dir is anchored there, so
// `-t http/cves/x.yaml` works against a pinned templates directory), else the
// templates directory itself. Empty means nuclei's own default directory.
func templateSources(dir string, templates []string) []string {
	if len(templates) == 0 {
		if dir != "" {
			return []string{dir}
		}
		return nil
	}
	out := make([]string, 0, len(templates))
	for _, t := range templates {
		if dir != "" && !filepath.IsAbs(t) {
			if _, err := os.Stat(t); err != nil {
				if _, err := os.Stat(filepath.Join(dir, t)); err == nil {
					t = filepath.Join(dir, t)
				}
			}
		}
		out = append(out, t)
	}
	return out
}

// Template setup states reported to a TemplatesProgress: started, then exactly
// one finished or failed. Nothing is reported when the templates are present.
const (
	TemplatesStarted  = "started"
	TemplatesFinished = "finished"
	TemplatesFailed   = "failed"
)

// TemplatesProgress receives EnsureTemplates' progress. dir is the clone
// target; err is set on TemplatesFailed.
type TemplatesProgress func(state, dir string, err error)

// installTemplates installs nuclei-templates from the (pinned) release archive
// over HTTPS — no git. A variable so tests can exercise EnsureTemplates
// without a network fetch.
var installTemplates = func(ctx context.Context, dir string, pin nucleitemplates.Pin) ([]byte, error) {
	if _, err := nucleitemplates.Install(ctx, dir, pin); err != nil {
		return nil, err
	}
	return nil, nil
}

// TemplatesDir resolves the directory nuclei templates load from: customDir
// when set, else ~/nuclei-templates.
func TemplatesDir(customDir string) (string, error) {
	if customDir != "" {
		return customDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("knownissuescan: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, "nuclei-templates"), nil
}

// TemplatesPresent reports whether the templates directory exists. No network.
func TemplatesPresent(customDir string) bool {
	dir, err := TemplatesDir(customDir)
	if err != nil {
		return false
	}
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// EnsureTemplates checks that the nuclei templates in cfg.TemplatesDir (or
// ~/nuclei-templates) are available and installs cfg.TemplatesPin if missing,
// unless cfg.Offline. Run calls it as its own guard; it is a no-op when the
// scan runner already provisioned the templates before the phase. When Vigolium embeds nuclei as a library, the automatic template
// download that the nuclei CLI performs does not run, so fresh environments
// (Docker, VPS) may not have templates installed.
//
// onProgress may be nil, in which case the clone is announced with text lines
// on stderr. With it, the caller renders the step (the scan runner turns it
// into an ETA line and a scan.setup event) and the text is suppressed.
func EnsureTemplates(cfg Config, onProgress TemplatesProgress) error {
	dir, err := TemplatesDir(cfg.TemplatesDir)
	if err != nil {
		return err
	}

	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return nil
	}
	if cfg.Offline {
		return fmt.Errorf("knownissuescan: nuclei templates not found at %s and --offline forbids downloading them; "+
			"provision them first (vigolium doctor --fix --only nuclei) or point --known-issue-scan-templates-dir at a copy", dir)
	}

	// A stateless (-S) scan writes nothing to $HOME, and a template clone is
	// hundreds of MB of state: fail closed with the way out.
	if paths.Stateless() {
		failure := fmt.Errorf("knownissuescan: nuclei templates not installed at %s; a stateless (-S) scan does not download them — "+
			"install first with `vigolium doctor --fix --only nuclei`, or point --known-issue-scan-templates-dir at a copy", dir)
		if onProgress != nil {
			onProgress(TemplatesFailed, dir, failure)
		}
		return failure
	}

	report := func(state string, err error) {
		if onProgress != nil {
			onProgress(state, dir, err)
		}
	}

	// Announced, not only logged through zap.
	//
	// This is a network fetch of a multi-hundred-megabyte git repo into shared
	// global state OUTSIDE the pinned database, triggered by the first
	// known-issue-scan a machine ever runs. Logging it at Info level meant it was
	// invisible without --verbose, so what the operator actually experienced was a
	// scan that hung for minutes on its first run with no explanation. A clone
	// that takes that long has to say so while it is happening.
	if onProgress == nil {
		fmt.Fprintf(os.Stderr, "%s nuclei templates not found at %s — cloning them now (one-time, several hundred MB; pin a directory with --known-issue-scan-templates-dir to skip)\n",
			"[known-issue-scan]", dir)
	}
	report(TemplatesStarted, nil)
	zap.L().Info("KnownIssueScan: nuclei templates not found, attempting to download",
		zap.String("path", dir))

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if out, err := installTemplates(ctx, dir, cfg.TemplatesPin); err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		failure := fmt.Errorf("knownissuescan: nuclei templates not found at %s and auto-download failed: %s\n"+
			"Install with: vigolium doctor --fix --only nuclei (or unpack %s into %s)",
			dir, detail, nucleitemplates.ArchiveURL(cfg.TemplatesPin.Version), dir)
		report(TemplatesFailed, failure)
		return failure
	}

	if onProgress == nil {
		fmt.Fprintf(os.Stderr, "%s nuclei templates ready at %s (took %s)\n",
			"[known-issue-scan]", dir, time.Since(started).Round(time.Second))
	}
	report(TemplatesFinished, nil)
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
