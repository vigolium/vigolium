package runner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// coversAllSeverities reports whether the configured severity list already
// includes every nuclei severity level, so the "widen the filter" tip can be
// suppressed. Order- and duplicate-insensitive; inputs are normalized.
func coversAllSeverities(sevs []string) bool {
	want := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	have := make(map[string]bool, len(sevs))
	for _, s := range sevs {
		have[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for s := range want {
		if !have[s] {
			return false
		}
	}
	return true
}

// formatKnownIssueScanTemplateScope renders the nuclei template selection (tags,
// excluded tags, and any custom templates dir) as a compact colored string for
// the KnownIssueScan phase header. Returns "all built-in" when no filters narrow
// the default template set.
func formatKnownIssueScanTemplateScope(cfg *config.KnownIssueScanConfig) string {
	var parts []string
	if len(cfg.Tags) > 0 {
		parts = append(parts, "tags="+terminal.HiTeal(strings.Join(cfg.Tags, ",")))
	}
	if len(cfg.ExcludeTags) > 0 {
		parts = append(parts, "exclude="+terminal.HiPurple(strings.Join(cfg.ExcludeTags, ",")))
	}
	if cfg.TemplatesDir != "" {
		parts = append(parts, "dir="+terminal.HiCyan(terminal.ShortenHome(config.ExpandPath(cfg.TemplatesDir))))
	}
	if n := len(cfg.Templates); n > 0 {
		parts = append(parts, "templates="+terminal.HiCyan(strconv.Itoa(n)))
	}
	if len(parts) == 0 {
		return terminal.Gray("all built-in")
	}
	return strings.Join(parts, " ")
}

// runKnownIssueScanPhase orchestrates nuclei + secret scan scanning.
func (r *Runner) runKnownIssueScanPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("KnownIssueScan", "assess security posture with Nuclei templates and third-party validation checks")
	var kisMaxDuration time.Duration
	if r.settings != nil {
		kisMaxDuration = r.settings.ScanningPace.ResolvePhase("known-issue-scan").MaxDuration
		if budget := PhaseSpeedDetail(r.settings, "known-issue-scan", 0); budget != "" {
			r.printPhaseDetail("Speed: " + budget)
		}

		// Surface the active severity filter and template scope as static detail
		// lines so the operator can see exactly what nuclei will run, not just how
		// many targets it runs against.
		sevDetail := terminal.Gray("all")
		if sevs := r.settings.KnownIssueScan.Severities; len(sevs) > 0 {
			sevDetail = terminal.HiTeal(strings.Join(sevs, ", "))
		}
		r.printPhaseDetail(fmt.Sprintf("Severities: %s", sevDetail))
		r.printPhaseDetail(fmt.Sprintf("Templates: %s", formatKnownIssueScanTemplateScope(&r.settings.KnownIssueScan)))
	}

	// bookkeepingCtx is the un-bounded parent context (still cancelled if the whole
	// scan is cancelled). End-of-phase DB writes use it so progress counters still
	// land when only a leg's deadline — not the scan — has fired. The Nuclei and
	// secret-scan legs below each derive their OWN max_duration budget from it (see
	// the per-leg comments), so they are bounded independently but never exceed the
	// overall scan budget.
	bookkeepingCtx := ctx
	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}
	if !enrichTargets && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
	}
	// Surface the active severity filter and how to widen it. An empty list means
	// "all severities", so only hint when the configured set does not already
	// cover all five (the default balanced intensity ships with critical+high).
	if r.settings != nil && !r.options.Silent {
		sevs := r.settings.KnownIssueScan.Severities
		if len(sevs) > 0 && !coversAllSeverities(sevs) {
			fmt.Fprintf(os.Stderr, "  %s %s %s\n",
				terminal.TipPrefix(),
				terminal.Gray(fmt.Sprintf("known-issue-scan limited to %s severities; scan all via", strings.Join(sevs, ","))),
				terminal.HiCyan(`vigolium config set known_issue_scan.severities "critical,high,medium,low,info"`))
		}
	}
	// Restrict KnownIssueScan to the same in-scope origins DynamicAssessment uses, so
	// targets/bodies from prior scans of other origins in this project (e.g. localhost
	// records on a different port left in the default project) don't leak into this scan.
	// Empty means no CLI targets/scope — fall back to a project-wide pass (mirrors DA).
	inScopeHosts := r.getInScopeDBHosts(ctx)

	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	if r.repository != nil && r.options.Verbose {
		paths, _ := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
		if len(paths) > 0 {
			var knownIssueScanTargets []string
			if enrichTargets {
				knownIssueScanTargets = buildKnownIssueScanTargetsFromPaths(paths)
			} else {
				knownIssueScanTargets = buildKnownIssueScanHostTargets(paths)
			}
			r.printVerboseTargets(knownIssueScanTargets)
		}
	}
	zap.L().Info("KnownIssueScan: running security posture assessment")

	// Collapse live output for findings that repeat the same extracted value
	// (e.g. one leaked secret seen on many URLs) into a single console line per
	// value. The grouper also owns the grouped severity tallies for the phase
	// summary; the full finding still streams to file/DB on every occurrence.
	grouper := newFindingGrouper(r.resolveFindingGrouping())

	onResult := func(result *output.ResultEvent) {
		if grouper.observe(result) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
			}
			// Echo to stderr when the stdout stream is deferred (jsonl/html), so
			// secret/CVE findings are visible live and not just post-scan. No-op
			// in console mode — r.output.Write above already printed them.
			r.echoLiveFinding("known-issue-scan", result)
		} else if err := r.output.WriteFileOnly(result); err != nil {
			zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
		}
	}

	// Nuclei scan on distinct hosts. It gets its OWN max_duration budget so that a
	// long Nuclei run no longer starves the secret scan below — the two
	// legs are bounded independently rather than sharing one budget. A ctx error
	// means this leg's max_duration (or the overall scan) elapsed — that is a
	// curtailment, not a failure.
	//
	// A first run clones nuclei-templates here, before the leg's deadline starts
	// (setup, not scanning). When the clone fails the nuclei leg is skipped and
	// the phase records the error; the secret scan below still runs.
	templatesErr := r.provisionNucleiTemplates(ctx, inScopeHosts)
	nucleiCtx, nucleiCancel := r.trackedPhaseDeadline(ctx, kisMaxDuration)
	defer nucleiCancel()
	if templatesErr != nil {
		zap.L().Error("KnownIssueScan: nuclei templates unavailable, skipping the nuclei leg", zap.Error(templatesErr))
		r.currentPhase.Load().noteError(templatesErr)
	} else if err := r.runKnownIssueScan(nucleiCtx, infra, onResult, inScopeHosts); err != nil {
		if nucleiCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: Nuclei scan stopped at phase max_duration", zap.Error(nucleiCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: Nuclei scan failed", zap.Error(err))
			r.currentPhase.Load().noteError(err)
		}
	}

	// secret scan on all response bodies. It gets a FRESH max_duration
	// budget that starts now (derived from the parent ctx, so still bounded by the
	// overall scan budget), so it always runs even when the Nuclei leg above was
	// curtailed at its deadline. secret scan reads DB response bodies locally (no
	// network) and normally finishes well within this budget. Worst-case phase
	// wall-clock is ~2× max_duration, capped by the overall scan budget. A ctx error
	// is a curtailment, distinct from a genuine scanner failure.
	secretScanCtx, secretScanCancel := r.trackedPhaseDeadline(ctx, kisMaxDuration)
	defer secretScanCancel()
	if err := r.runSecretScanBatch(secretScanCtx, infra, onResult, inScopeHosts); err != nil {
		if secretScanCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: secret scan curtailed before all response bodies were scanned — phase max_duration reached", zap.Error(secretScanCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: secret scan failed", zap.Error(err))
			r.currentPhase.Load().noteError(err)
		}
	}

	// Print summary using grouped tallies (repeats of the same value count once),
	// then one muted rollup line per collapsed value noting how many URLs it spanned.
	counts := grouper.summaryCounts()
	var total int
	for _, c := range counts {
		total += c
	}
	if total > 0 {
		r.printPhaseDetail(formatKnownIssueScanSummary(counts, total))
		for _, line := range grouper.rollupLines() {
			r.printPhaseDetail(line)
		}
	}

	// Increment processed_count for KnownIssueScan phase using the raw finding
	// count — every emitted finding was written to the DB at this point (the
	// post-phase grouping pass merges them afterward). Use the un-bounded parent
	// ctx so the counter still updates when the phase deadline fired mid-scan.
	if r.repository != nil && total > 0 {
		if err := r.repository.IncrementProcessedCount(bookkeepingCtx, infra.scanUUID, int64(grouper.rawTotal())); err != nil {
			zap.L().Warn("KnownIssueScan: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("KnownIssueScan", fmt.Sprintf("completed in %s", terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// runKnownIssueScan executes known issue scanning using the nuclei Go library.
// inScopeHosts restricts targets to the current scan's in-scope origins (scheme/host/port;
// empty = project-wide pass, mirroring DynamicAssessment), so records left in the project
// by prior scans of other origins don't leak into this scan's targets.
func (r *Runner) runKnownIssueScan(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent), inScopeHosts []database.HostTarget) error {
	if r.repository == nil {
		return fmt.Errorf("known-issue-scan: database repository required")
	}

	// Query distinct paths from DB (scoped to in-scope origins) and build targets
	paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
	if err != nil {
		return fmt.Errorf("known-issue-scan: failed to query paths: %w", err)
	}
	if len(paths) == 0 {
		zap.L().Info("KnownIssueScan: no hosts in database, skipping")
		return nil
	}

	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}

	var targets []string
	if enrichTargets {
		targets = buildKnownIssueScanTargetsFromPaths(paths)
	} else {
		targets = buildKnownIssueScanHostTargets(paths)
	}

	zap.L().Info("KnownIssueScan: targets from database",
		zap.Int("count", len(targets)),
		zap.Int("in_scope_origins", len(inScopeHosts)))

	// Build KnownIssueScan config from settings
	cfg := knownissuescan.Config{
		Targets:     targets,
		Concurrency: r.options.Concurrency,
		ScanUUID:    r.options.ScanUUID,
		ProjectUUID: r.options.ProjectUUID,
		ProxyURL:    r.options.ProxyURL,
		// nuclei runs its own HTTP stack, so it cannot use the assessment
		// requester's view — it needs the headers themselves. Under
		// use_in_discovery: false this is the only way the primary session
		// reaches this phase; it previously ran unauthenticated.
		Headers:    r.assessmentHeaderSlice(infra),
		OnResult:   onResult,
		Repository: r.repository,
		// nuclei owns its own HTTP stack, so it cannot page through the shared
		// requester. These hooks give it the next best thing: the shared
		// requester's block detection and the limiter's per-host verdict, so this
		// phase stops being the one active phase that can neither slow down nor
		// say that it was blocked.
		Edge: r.knownIssueScanEdge(infra),
	}

	// Apply YAML settings
	if r.settings != nil {
		knownIssueScanCfg := &r.settings.KnownIssueScan
		cfg.Tags = knownIssueScanCfg.Tags
		cfg.ExcludeTags = knownIssueScanCfg.ExcludeTags
		cfg.Severities = knownIssueScanCfg.Severities
		cfg.SeverityOverrides = knownIssueScanCfg.SeverityOverrides
		if knownIssueScanCfg.TemplatesDir != "" {
			cfg.TemplatesDir = config.ExpandPath(knownIssueScanCfg.TemplatesDir)
		}
		for _, t := range knownIssueScanCfg.Templates {
			cfg.Templates = append(cfg.Templates, config.ExpandPath(t))
		}

		// scanning_pace.known-issue-scan controls speed
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		cfg.Concurrency = r.phaseConcurrency("known-issue-scan")
		if knownIssueScanPace.RateLimit > 0 {
			cfg.RateLimit = knownIssueScanPace.RateLimit
		}
		if knownIssueScanPace.MaxDuration > 0 {
			cfg.Timeout = knownIssueScanPace.MaxDuration
		}
	}

	return knownissuescan.Run(ctx, cfg)
}
