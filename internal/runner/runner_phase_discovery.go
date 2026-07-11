package runner

import (
	"bufio"
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

func (r *Runner) runDiscoveryPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	var sources []source.InputSource
	var discoveryTargets []string

	expandSeedParents := false
	if r.settings != nil {
		expandSeedParents = r.settings.Discovery.ExpandSeedParents
	}

	// Decide up front whether to auto-enable FUZZ fuzzing (must be set before
	// buildDeparosConfig/resolveDiscoveryWordlists read discoveryFuzzingState).
	// Reset first so shouldAutoFuzzDiscovery's "already fuzzing" check reads the
	// explicit modes only, not a value left over from a prior run on a reused
	// Runner (agent rescans).
	r.autoFuzzDiscovery = false
	r.autoFuzzDiscovery = r.shouldAutoFuzzDiscovery()

	var discoverSrc *source.DeparosDiscoverySource
	if r.options.DiscoverEnabled && len(r.options.Targets) > 0 {
		// In-scope origins (scheme/host/port) for this scan's CLI targets, shared by the
		// host-URL expansion and the path enrichment below so neither pulls in records
		// left by prior scans of a different origin (e.g. a different port on the host).
		inScopeHosts := r.getInScopeDBHosts(ctx)
		additionalTargets := hostURLsFromHostTargets(inScopeHosts)

		// When auto-fuzzing, keep the off-host SSO/login domain(s) the target
		// redirected to out of scope — fuzz the original target host for hidden
		// routes, not the identity provider.
		if r.autoFuzzDiscovery && len(r.spidering.ssoHosts) > 0 {
			before := len(additionalTargets)
			additionalTargets = filterOutHosts(additionalTargets, r.spidering.ssoHosts)
			if removed := before - len(additionalTargets); removed > 0 {
				zap.L().Info("Discovery: excluded SSO redirect host(s) from fuzzing scope",
					zap.Int("removed", removed), zap.Strings("hosts", r.spidering.ssoHosts))
			}
		}

		if expandSeedParents {
			expanded := discovery.ExpandSeedParents(r.options.Targets)
			before := len(additionalTargets)
			additionalTargets = dedupTargets(additionalTargets, expanded)
			added := len(additionalTargets) - before
			zap.L().Info("Discovery: expanded seed URLs into parent directories",
				zap.Int("seeds", len(r.options.Targets)),
				zap.Int("parents_added", added))
		}

		enrichTargets := false
		if r.settings != nil {
			enrichTargets = r.settings.Discovery.EnrichTargets
		}
		if enrichTargets && r.repository != nil {
			pathTargets, pathErr := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
			if pathErr != nil {
				zap.L().Warn("Discovery: failed to get DB paths for enrichment", zap.Error(pathErr))
			} else if len(pathTargets) > 0 {
				pathURLs := buildDiscoveryTargetsFromPaths(pathTargets)
				additionalTargets = dedupTargets(additionalTargets, pathURLs)
				zap.L().Info("Discovery: enriched targets with paths from prior phases",
					zap.Int("path_targets", len(pathURLs)))
			}
		}

		discoveryTargets = dedupTargets(r.options.Targets, additionalTargets)
		deparosCfg := r.buildDeparosConfig(additionalTargets)
		src, srcErr := source.NewDeparosDiscoverySource(deparosCfg)
		if srcErr != nil {
			zap.L().Warn("Failed to initialize deparos discovery", zap.Error(srcErr))
		} else {
			discoverSrc = src
			sources = append(sources, discoverSrc)
		}
	} else {
		discoveryTargets = r.options.Targets
	}

	sources = append(sources, r.inputSource)

	var compositeSource source.InputSource
	if len(sources) == 1 {
		compositeSource = sources[0]
	} else {
		compositeSource = source.NewConcurrentMultiSource(sources...)
	}

	r.printPhaseStart("Discovery", "ingest inputs and discover directories, files, and hidden endpoints via Deparos content discovery")

	speedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		discPace := r.settings.ScanningPace.ResolvePhase("discovery")
		if discPace.MaxDuration > 0 {
			speedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(discPace.MaxDuration.String()))
		}
		if discPace.DurationFactor > 0 {
			speedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", discPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(speedDetail)

	// Content-discovery status: whether deparos runs this phase (vs. plain input
	// ingestion), the dictionary wordlists feeding it, and whether FUZZ fuzzing is
	// on — each on its own line. Shown unconditionally because "is this scan
	// discovering/fuzzing, and with what" is the first thing operators ask of the
	// Discovery phase.
	r.printDiscoveryStatusLines(discoverSrc != nil)

	if r.autoFuzzDiscovery && !r.options.Silent {
		reason := fmt.Sprintf("spidering found little content (%d records)", r.spidering.records)
		if r.spidering.sawSSO {
			reason = "spidering hit an SSO/login wall"
		}
		msg := fmt.Sprintf("%s Fuzzing auto-enabled — %s; brute-forcing %s for hidden routes",
			terminal.Yellow(terminal.SymbolArrow),
			reason,
			terminal.Orange("the original target(s)"))
		if len(r.spidering.ssoHosts) > 0 {
			msg += terminal.Gray(fmt.Sprintf(" (excluding SSO host(s): %s)", strings.Join(r.spidering.ssoHosts, ", ")))
		}
		r.printPhaseDetail(msg)
	}

	showDiscoveryConfig := r.options.Verbose || strings.EqualFold(r.options.Intensity, "deep")
	if r.settings != nil && showDiscoveryConfig {
		discCfg := &r.settings.Discovery
		recursion := "off"
		if discCfg.Recursion.Enabled {
			recursion = fmt.Sprintf("max_depth=%d", discCfg.Recursion.MaxDepth)
		}
		intensity := r.options.Intensity
		if intensity == "" {
			intensity = "default"
		}
		configDetail := fmt.Sprintf("Config: mode=%s, scope=%s, recursion=%s, intensity=%s, malformed_path_probe=%s, backup_ext=%s, numeric_fuzz=%s, enrich_targets=%s, expand_seed_parents=%s",
			terminal.HiTeal(discCfg.Mode),
			terminal.HiTeal(discCfg.ScopeMode),
			terminal.HiTeal(recursion),
			terminal.HiTeal(intensity),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.EnableMalformedPathProbe)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.Extensions.TestBackupExtensions)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.Wordlists.EnableNumericFuzzing)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.EnrichTargets)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.ExpandSeedParents)))
		r.printPhaseDetail(configDetail)
	}

	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(discoveryTargets)

	if fuzzEnabled, _ := r.discoveryFuzzingState(); !fuzzEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enable on-the-fly directory fuzzing with a custom wordlist via"), terminal.HiCyan("--fuzz-wordlist <path>"))
	}

	enrichTargetsEnabled := false
	if r.settings != nil {
		enrichTargetsEnabled = r.settings.Discovery.EnrichTargets
	}
	if !enrichTargetsEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich discovery targets with discovered paths via"), terminal.HiCyan("vigolium config discovery.enrich_targets=true"))
	}

	zap.L().Info("Discovery: ingesting input into database")

	var discoveryRecordWriter *database.RecordWriter
	if r.repository != nil {
		discoveryRecordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	}

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  discoveryRecordWriter,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("discovery"),
		// Deparos already captured a response for each crawled URL and emits it on
		// the work item (deparos_discovery.go saveAndEmit); reuse it instead of
		// issuing a second identical request per URL. Request-only items (spec-
		// endpoint stubs, which carry no response) still fall through to a single
		// baseline fetch in fetchBaselineResponse, so routes aren't left empty.
		SkipBaseline: true,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	var discoveryPassive []modules.PassiveModule
	if r.settings != nil && len(r.settings.Discovery.PassiveModuleTags) > 0 {
		ids := modules.ResolveModuleTags(r.settings.Discovery.PassiveModuleTags)
		if len(ids) > 0 {
			discoveryPassive = modules.GetPassiveModulesByIDs(ids)
			if len(discoveryPassive) > 0 {
				zap.L().Info("Discovery: passive modules enabled",
					zap.Int("count", len(discoveryPassive)),
					zap.Strings("tags", r.settings.Discovery.PassiveModuleTags))
			}
		}
	}

	executor := core.NewExecutor(executorCfg, compositeSource, nil, discoveryPassive)
	_, err := executor.Execute(ctx)
	if discoveryRecordWriter != nil {
		discoveryRecordWriter.Close()
	}
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Discovery: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Discovery", fmt.Sprintf("completed — %s items ingested (deparos=%s) in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())),
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled)),
		terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("Discovery: completed", zap.Int64("processed", executor.Processed()))

	if discoverSrc != nil {
		stats := discoverSrc.Stats()
		if stats.TotalDiscovered > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("discovered %s records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.TotalDiscovered)),
				formatStatusCodeArray(stats.AllCodes)))
		}
		if stats.HardDedupRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("deduplicated %s redundant records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.HardDedupRemoved)),
				formatStatusCodeArray(stats.DedupedCodes)))
		}
		if stats.FuzzyCappedRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("capped %s near-identical responses (max %s kept per cluster) — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.FuzzyCappedRemoved)),
				terminal.HiTeal(fmt.Sprintf("%d", stats.ClusterCap)),
				formatStatusCodeArray(stats.CappedCodes)))
		}
	}

	return nil
}

// printDiscoveryStatusLines prints the Discovery phase's content-discovery status
// and, when deparos is active, its wordlist and fuzzing lines as separate detail
// rows. deparosActive mirrors the runDiscoveryPhase gate (DiscoverEnabled &&
// targets present && source init succeeded).
func (r *Runner) printDiscoveryStatusLines(deparosActive bool) {
	if !deparosActive {
		r.printPhaseDetail(fmt.Sprintf("Content discovery: %s — %s",
			terminal.Orange("disabled"), terminal.Gray(r.discoveryDisabledReason())))
		return
	}
	r.printPhaseDetail(fmt.Sprintf("Content discovery: %s (deparos)", terminal.HiTeal("enabled")))
	r.printPhaseDetail("Wordlists: " + r.discoveryWordlistSummary())
	r.printPhaseDetail("Fuzzing: " + r.discoveryFuzzingSummary())
}

// discoveryDisabledReason explains why deparos content discovery is not running,
// so a plain ingest-only Discovery phase doesn't read as a silent no-op.
func (r *Runner) discoveryDisabledReason() string {
	switch {
	case !r.options.DiscoverEnabled:
		return "deparos off for this run (enable with --discover or a deeper strategy) — ingest-only"
	case len(r.options.Targets) == 0:
		return "no CLI seed targets for deparos — ingest-only"
	default:
		return "deparos unavailable (init failed, see runtime log) — ingest-only"
	}
}

// discoveryWordlistSummary names the dictionary wordlists (short/long file & dir)
// feeding deparos, plus which "observed" token sources (names/paths/files
// harvested while crawling) are on. Lists are tagged embedded vs operator-supplied
// by comparing their directory to the materialized-defaults dir. The fuzz list is
// reported separately by discoveryFuzzingSummary, so it is excluded here.
func (r *Runner) discoveryWordlistSummary() string {
	w := r.resolveDiscoveryWordlists()
	embeddedDir := wordlistDir()

	var dicts []string
	var anyEmbedded, anyConfigured bool
	for _, p := range []string{w.shortFile, w.longFile, w.shortDir, w.longDir} {
		if p == "" {
			continue
		}
		dicts = append(dicts, formatWordlistEntry(p))
		if filepath.Dir(p) == embeddedDir {
			anyEmbedded = true
		} else {
			anyConfigured = true
		}
	}

	var observed []string
	if r.settings != nil {
		wl := r.settings.Discovery.Wordlists
		if wl.UseObservedNames {
			observed = append(observed, "names")
		}
		if wl.UseObservedPaths {
			observed = append(observed, "paths")
		}
		if wl.UseObservedFiles {
			observed = append(observed, "files")
		}
	}

	var parts []string
	if len(dicts) > 0 {
		// Each dict is already colored (name + orange count), so join without an
		// outer color wrap and append the source tag in gray.
		label := strings.Join(dicts, ", ")
		switch {
		case anyEmbedded && anyConfigured:
			label += " " + terminal.Gray("(incl. embedded defaults)")
		case anyEmbedded:
			label += " " + terminal.Gray("(embedded defaults)")
		}
		parts = append(parts, label)
	} else {
		parts = append(parts, terminal.Orange("observed-only (no dictionary resolved)"))
	}
	if len(observed) > 0 {
		parts = append(parts, terminal.Gray("observed "+strings.Join(observed, "+")))
	}
	return strings.Join(parts, " | ")
}

// formatWordlistEntry renders a wordlist path as "<basename> (<count>)" with the
// basename in teal and the entry count in orange. The count is omitted when the
// file can't be read.
func formatWordlistEntry(path string) string {
	entry := terminal.HiTeal(filepath.Base(path))
	if n := wordlistEntryCount(path); n >= 0 {
		entry += " " + terminal.Orange(fmt.Sprintf("(%d)", n))
	}
	return entry
}

// wordlistEntryCount counts non-empty, whitespace-trimmed lines in a wordlist
// file, matching how deparos loads it (pkg/deparos/discovery/payload loadWordlist).
// Returns -1 on read error so callers can omit the count rather than show a wrong 0.
func wordlistEntryCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()

	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	if sc.Err() != nil {
		return -1
	}
	return count
}

// discoveryFuzzingSummary reports whether deparos FUZZ fuzzing is on (it appends
// /FUZZ and brute-forces the fuzz wordlist), the wordlist in play, and why.
func (r *Runner) discoveryFuzzingSummary() string {
	enabled, reason := r.discoveryFuzzingState()
	if !enabled {
		return fmt.Sprintf("%s — %s", terminal.Orange("disabled"), terminal.Gray(reason))
	}

	w := r.resolveDiscoveryWordlists()
	src := "embedded default"
	if r.options.FuzzWordlistPath != "" {
		src = "via --fuzz-wordlist"
	}
	list := terminal.HiTeal("fuzz.txt")
	if w.fuzz != "" {
		list = formatWordlistEntry(w.fuzz)
	}
	return fmt.Sprintf("%s — %s (%s), appends /FUZZ %s",
		terminal.HiTeal("enabled"),
		list,
		terminal.Gray(src),
		terminal.Gray("["+reason+"]"))
}

// seedCLITargets ingests CLI targets into the database without running deparos or modules.
// This is used when discovery is skipped but downstream phases (KnownIssueScan, DynamicAssessment)
// need DB records to operate on.
func (r *Runner) seedCLITargets(ctx context.Context, infra *phaseInfra) error {
	r.printPhaseStart("Seed", "ingest CLI targets into database (discovery skipped)")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("seed"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, r.inputSource, nil, nil)
	_, err := executor.Execute(ctx)
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Seed: failed to increment processed count", zap.Error(err))
		}
	}

	zap.L().Info("Seed: CLI targets ingested", zap.Int64("processed", executor.Processed()))
	r.printPhaseComplete("Seed", fmt.Sprintf("completed — %s items ingested",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed()))))
	return nil
}

// spideringPhaseBudgetCap bounds how many per-target max-duration budgets the
// whole spidering phase may consume. Each target still gets its own full
// max-duration; the overall phase deadline is max-duration × min(targets, cap),
// so a small target list is unaffected while a large merged list (CLI targets +
// many in-scope DB hosts) can't blow the phase out to len(targets) × max-duration.
const spideringPhaseBudgetCap = 8

// spideringPhaseCeiling returns the overall wall-clock budget for the spidering
// phase. Each of numTargets gets up to maxDuration, but the total is capped at
// max-duration × min(numTargets, spideringPhaseBudgetCap). A non-positive
// maxDuration (unlimited) or non-positive target count returns 0, meaning "no
// ceiling" — the caller should then run without a phase deadline.
func spideringPhaseCeiling(maxDuration time.Duration, numTargets int) time.Duration {
	if maxDuration <= 0 || numTargets <= 0 {
		return 0
	}
	return maxDuration * time.Duration(min(numTargets, spideringPhaseBudgetCap))
}

// spideringTeardownGrace is how long past a target's max-duration the watchdog
// waits before declaring RunSpider wedged. Legitimate teardown (browser/page
// close, record-writer drain) is bounded and quick; this only fires on a true
// hang — e.g. an unresponsive/anti-bot browser, or a rod CDP call without a
// bound — guaranteeing the spidering phase can never block the scan forever.
const spideringTeardownGrace = 90 * time.Second

// runWithWatchdog runs work in a goroutine and returns its result, or — if work
// does not finish within timeout — calls onTimeout and returns that instead. The
// work goroutine is abandoned on timeout (it leaks until it finishes on its own,
// if ever), which is the whole point: a wedged operation can never block the
// caller past timeout. The done channel is buffered so a late-finishing
// abandoned worker never blocks on send. Generic + side-effect-free so it can be
// unit-tested without a browser.
func runWithWatchdog[T any](timeout time.Duration, work func() T, onTimeout func() T) T {
	done := make(chan T, 1)
	go func() { done <- work() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case v := <-done:
		return v
	case <-timer.C:
		return onTimeout()
	}
}

// runSpiderWatchdog runs spitolas.RunSpider (and closes rw) under a hard
// watchdog: it always returns within budget + spideringTeardownGrace. If the run
// wedges past that, it logs a full goroutine dump (so the stuck call site is
// diagnosable) and returns an error rather than hanging the scan; the stuck run
// and its browser are abandoned and leak until the process exits. rw is closed
// inside the worker so a stuck close is abandoned with it, not awaited.
func runSpiderWatchdog(ctx context.Context, cfg spitolas.SpiderConfig, rw *database.RecordWriter, budget time.Duration, target string) (*spitolas.SpiderResult, error) {
	type outcome struct {
		res *spitolas.SpiderResult
		err error
	}
	oc := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() outcome {
			res, err := spitolas.RunSpider(ctx, cfg, rw)
			rw.Close()
			return outcome{res, err}
		},
		func() outcome {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			zap.L().Error("Spidering watchdog fired — RunSpider did not return within budget+grace; abandoning the run (browser/goroutines leak until exit)",
				zap.String("target", target),
				zap.Duration("budget", budget),
				zap.Duration("grace", spideringTeardownGrace))
			zap.L().Warn("Spidering watchdog goroutine dump follows:\n" + string(buf[:n]))
			return outcome{nil, fmt.Errorf("spidering watchdog timeout for %s (exceeded %s)", target, budget+spideringTeardownGrace)}
		},
	)
	return oc.res, oc.err
}

// runReSpiderSessionCrawl runs one seed on a shared SpiderSession under the same
// hang-proofing as runSpiderWatchdog: if Crawl does not return within budget+grace
// the run is abandoned (the shared browser/goroutines leak until exit) and an
// error is returned so the caller abandons the whole host session.
func runReSpiderSessionCrawl(ctx context.Context, sess *spitolas.SpiderSession, seedURL string, budget time.Duration) (*spitolas.SpiderResult, error) {
	type outcome struct {
		res *spitolas.SpiderResult
		err error
	}
	oc := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() outcome {
			res, err := sess.Crawl(ctx, seedURL)
			return outcome{res, err}
		},
		func() outcome {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			zap.L().Error("Re-spider session-crawl watchdog fired — abandoning the host session (browser/goroutines leak until exit)",
				zap.String("seed", seedURL),
				zap.Duration("budget", budget),
				zap.Duration("grace", spideringTeardownGrace))
			zap.L().Warn("Re-spider watchdog goroutine dump follows:\n" + string(buf[:n]))
			return outcome{nil, fmt.Errorf("re-spider session crawl watchdog timeout for %s (exceeded %s)", seedURL, budget+spideringTeardownGrace)}
		},
	)
	return oc.res, oc.err
}

// closeReSpiderSession flushes and tears down a shared SpiderSession (and its
// backing RecordWriter) under a teardown watchdog, so a wedged browser close
// can't hang the phase.
func closeReSpiderSession(sess *spitolas.SpiderSession, rw *database.RecordWriter) {
	_ = runWithWatchdog(
		spideringTeardownGrace,
		func() struct{} {
			_ = sess.Close()
			rw.Close()
			return struct{}{}
		},
		func() struct{} {
			zap.L().Error("Re-spider session-close watchdog fired — browser teardown wedged; leaking until exit")
			return struct{}{}
		},
	)
}

// runSpideringPhase runs browser-based crawling using spitolas.
// Captured traffic is stored in vigolium's HTTPRecord table via RepositoryWriter.
// Targets are merged from CLI targets and in-scope hosts discovered by prior phases.
func (r *Runner) runSpideringPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil {
		return fmt.Errorf("spidering requires a database repository")
	}

	phaseStart := time.Now()
	r.printPhaseStart("Spidering", "browser-based crawling to discover dynamic content and API endpoints")

	settingsCfg := r.settings.Spidering
	// VIGOLIUM_BROWSER_HEADED (set by the agent --headed flag) forces a visible
	// browser window even when settings default to headless. settingsCfg is a
	// value copy, so this never mutates shared settings. This is the same env
	// override ProbeURL honors, extended here so agent pre-scan / --discover
	// spidering is visible too — not just the in-process browser probes.
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		settingsCfg.Headless = false
	}
	maxDuration := settingsCfg.MaxDurationParsed()
	if r.options.SpideringMaxDuration > 0 {
		maxDuration = r.options.SpideringMaxDuration
	}

	targets := r.options.Targets
	dbHosts := r.getInScopeHostURLs(ctx)
	targets = dedupTargets(targets, dbHosts)

	expandSeedParents := false
	if r.settings != nil {
		expandSeedParents = r.settings.Discovery.ExpandSeedParents
	}
	var parentsAdded int
	if expandSeedParents && len(r.options.Targets) > 0 {
		expanded := discovery.ExpandSeedParents(r.options.Targets)
		before := len(targets)
		targets = dedupTargets(targets, expanded)
		parentsAdded = len(targets) - before
	}

	zap.L().Info("Spidering: merged targets",
		zap.Int("cli", len(r.options.Targets)),
		zap.Int("from_db", len(dbHosts)),
		zap.Int("parents_added", parentsAdded),
		zap.Int("total", len(targets)))

	if r.heuristicsResults != nil {
		before := len(targets)
		targets = filterTargetsByHeuristics(targets, r.heuristicsResults, func(hr *HeuristicsResult) bool {
			return hr.SkipSpidering
		})
		if skipped := before - len(targets); skipped > 0 {
			zap.L().Info("Spidering: targets filtered by heuristics",
				zap.Int("skipped", skipped), zap.Int("remaining", len(targets)))
		}
		if len(targets) == 0 {
			r.printPhaseComplete("Spidering", "skipped — all targets excluded by heuristics check")
			return nil
		}
	}

	formsState := "on"
	if settingsCfg.NoForms {
		formsState = "off"
	}
	configDetail := fmt.Sprintf("Config: strategy=%s, max-depth=%s, max-states=%s, forms=%s, headless=%s, max-duration=%s",
		terminal.HiTeal(settingsCfg.Strategy),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxDepth)),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxStates)),
		terminal.HiTeal(formsState),
		terminal.HiTeal(fmt.Sprintf("%v", settingsCfg.Headless)),
		terminal.HiTeal(maxDuration.String()))
	if r.settings != nil {
		spiderPace := r.settings.ScanningPace.ResolvePhase("spidering")
		if spiderPace.DurationFactor > 0 {
			configDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", spiderPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(configDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(targets)))
	r.printVerboseTargets(targets)

	// Per-target budget with an overall phase ceiling. Each target still gets
	// its own full max-duration, but the whole phase is bounded so a large
	// merged target list (CLI targets + many in-scope DB hosts) can't make
	// spidering run for len(targets) × max-duration. The ceiling is
	// max-duration × min(targets, spideringPhaseBudgetCap); each per-target
	// context derives from it, so the last target before the ceiling gets
	// whatever budget remains and any targets beyond it are skipped (logged).
	// phaseDeadline treats a zero ceiling (unlimited max-duration) as unbounded.
	phaseCeiling := spideringPhaseCeiling(maxDuration, len(targets))
	phaseCtx, phaseCancel := phaseDeadline(ctx, phaseCeiling)
	defer phaseCancel()

	var totalStates, totalActions, totalRecords int
	var ssoHosts []string
	var skippedTargets int

	// Carry the browser's WAF/bot-cleared session (cookies + optionally its UA)
	// forward into discovery and scanning. On by default; scoped per-host below.
	// The UA is only pinned when the operator opted away from the honest "preset"
	// default (a custom/random UA or VIGOLIUM_DEFAULT_UA) — otherwise the honest
	// self-identifying UA is left untouched. Clearance cookies stay valid because
	// downstream requests keep the same UA the WAF issued them to.
	carrySession := r.options.CarryBrowserSession
	carryUA := !httpmsg.UserAgentIsHonestPreset()
	var harvested map[string]httpmsg.CarriedSession
	if carrySession {
		harvested = make(map[string]httpmsg.CarriedSession)
	}

	for i, target := range targets {
		// Overall ceiling exhausted — skip the remaining targets rather than
		// launching crawls against an already-expired context.
		if phaseCtx.Err() != nil {
			skippedTargets = len(targets) - i
			zap.L().Warn("Spidering: phase budget ceiling reached, skipping remaining targets",
				zap.Int("skipped", skippedTargets),
				zap.Int("total", len(targets)),
				zap.Duration("max_duration", maxDuration),
				zap.Int("budget_cap", spideringPhaseBudgetCap))
			break
		}
		zap.L().Info("Spidering target", zap.String("target", target))

		loginCredsAttempts, loginCredsFull := loginCredsPolicy(r.options.Intensity)
		// Bridge the operator's session/custom headers into the browser so the
		// crawl explores authenticated content, not just the login shell.
		browserCookies, browserHeaders := browserAuthFromHeaders(r.options.Headers)
		cfg := spitolas.SpiderConfig{
			TargetURL:           target,
			MaxDepth:            settingsCfg.MaxDepth,
			MaxStates:           settingsCfg.MaxStates,
			MaxDuration:         maxDuration,
			MaxConsecutiveFails: settingsCfg.MaxConsecutiveFails,
			Headless:            settingsCfg.Headless,
			BrowserCount:        settingsCfg.BrowserCount,
			Strategy:            settingsCfg.Strategy,
			IncludeResponseBody: settingsCfg.IncludeResponseBody,
			IncludeHeaders:      true,
			Silent:              r.options.Silent,
			Verbose:             r.options.Verbose,
			BrowserEngine:       settingsCfg.BrowserEngine,
			BrowserPath:         settingsCfg.BrowserPath,
			NoCDP:               settingsCfg.NoCDP,
			NoForms:             settingsCfg.NoForms,
			ProxyURL:            r.options.ProxyURL,
			// Common-credential login attempts against confirmed local login
			// forms: on at balanced (minimal list) and deep (full list), off at
			// quick/lite (lockout/authorization risk).
			LoginCredentialAttempts: loginCredsAttempts,
			LoginCredentialFullList: loginCredsFull,
			InitialCookies:          browserCookies,
			ExtraHeaders:            browserHeaders,
		}

		if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
			sm := infra.scopeMatcher
			cfg.ScopeFilter = func(host, path string) bool {
				return sm.InScopeRequest(host, path, "", "")
			}
		}

		rw := database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		// Derive from phaseCtx so the per-target budget is min(max-duration,
		// remaining phase ceiling) — the overall cap is enforced automatically.
		// The watchdog guarantees this returns within budget+grace even if the
		// browser/teardown wedges, so a single target can never hang the scan.
		timeoutCtx, cancel := context.WithTimeout(phaseCtx, maxDuration)
		result, err := runSpiderWatchdog(timeoutCtx, cfg, rw, maxDuration, target)
		cancel()

		if err != nil {
			zap.L().Error("Spidering failed",
				zap.String("target", target), zap.Error(err))
			continue
		}

		totalStates += result.StatesDiscovered
		totalActions += result.ActionsExecuted
		totalRecords += result.RecordsSaved

		if carrySession && len(result.HarvestedCookies) > 0 {
			// Scope the session to the host the crawl actually settled on: the
			// adopted/landing host when the start URL relocated off-host, else the
			// target host.
			sessionHost := httpmsg.HostnameFromURL(target)
			if result.HostAdopted && result.LandingURL != "" {
				if adopted := httpmsg.HostnameFromURL(result.LandingURL); adopted != "" {
					sessionHost = adopted
				}
			}
			if cookieHeader := httpmsg.FlattenCookiesForHost(sessionHost, result.HarvestedCookies); cookieHeader != "" {
				sess := httpmsg.CarriedSession{CookieHeader: cookieHeader}
				if carryUA {
					sess.UserAgent = result.BrowserUserAgent
				}
				harvested[sessionHost] = sess
			}
		}

		zap.L().Info("Spidering completed for target",
			zap.String("target", target),
			zap.Int("states", result.StatesDiscovered),
			zap.Int("actions", result.ActionsExecuted),
			zap.Int("records_saved", result.RecordsSaved))

		// A landing whose "Log on" CTA was driven means the crawler entered the
		// app's OAuth/SAML/SSO flow — surface it so the captured login-flow URLs
		// aren't a surprise.
		if result.LoginCTADriven {
			zap.L().Info("Spidering: drove login CTA into the auth flow",
				zap.String("target", target),
				zap.String("cta", result.LoginCTAText))
			r.printPhaseDetail(fmt.Sprintf("%s clicked the %s call-to-action on %s to enter and capture the OAuth/SAML login flow.",
				terminal.Purple(terminal.SymbolArrow),
				terminal.Orange(fmt.Sprintf("%q", result.LoginCTAText)),
				terminal.Gray(target)))
		}

		// The start URL bounced the browser off-host. Two cases: a login/SSO wall
		// (the crawler can't go past it unauthenticated, so the run yields next
		// to nothing — advise auth), or a relocated app on another host (the
		// crawler adopts that host and crawls it). Either way, say so — a silent
		// near-empty result otherwise reads like the site has no content.
		switch {
		case result.OffHostRedirect && result.LandingIsLogin:
			if lu, perr := neturl.Parse(result.LandingURL); perr == nil && lu.Host != "" {
				ssoHosts = append(ssoHosts, lu.Host)
			}
			zap.L().Warn("Spidering: start URL redirected off-host to a login wall",
				zap.String("target", target),
				zap.String("landing", result.LandingURL))
			r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — likely an SSO/login wall. The crawler stays in scope, so little was discovered. Supply authentication (--auth) or add the redirect host to scope to crawl behind the login.",
				terminal.Yellow(terminal.SymbolArrow),
				terminal.Gray(target),
				terminal.Yellow(result.LandingURL)))
		case result.OffHostRedirect && result.HostAdopted:
			zap.L().Info("Spidering: adopted off-host redirect target into scope",
				zap.String("target", target),
				zap.String("landing", result.LandingURL))
			r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — not a login page, so its host was added to scope and crawled.",
				terminal.Purple(terminal.SymbolArrow),
				terminal.Gray(target),
				terminal.Orange(result.LandingURL)))
		case result.OffHostRedirect:
			zap.L().Info("Spidering: start URL redirected off-host",
				zap.String("target", target),
				zap.String("landing", result.LandingURL))
			r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s.",
				terminal.Purple(terminal.SymbolArrow),
				terminal.Gray(target),
				terminal.Orange(result.LandingURL)))
		}
	}

	// Carry the harvested per-host sessions forward: store them for the Discovery
	// phase (buildDeparosConfig reads r.browserSessions) and inject them into the
	// shared scan requester used by discovery ingestion and dynamic assessment.
	// The requester is shared across all phases (executeNativePhase threads one
	// infra), so a single injection reaches every downstream request.
	if len(harvested) > 0 {
		r.browserSessions = harvested
		if infra.httpRequester != nil {
			infra.httpRequester.SetCarriedSessions(harvested)
		}
		hosts := make([]string, 0, len(harvested))
		for h := range harvested {
			hosts = append(hosts, h)
		}
		zap.L().Info("Spidering: carried browser session forward",
			zap.Strings("hosts", hosts), zap.Bool("pin_user_agent", carryUA))
		uaNote := ""
		if carryUA {
			uaNote = " and pinned its User-Agent"
		}
		r.printPhaseDetail(fmt.Sprintf("%s Carried the browser's cleared session (cookies%s) forward to discovery and scanning for %s.",
			terminal.Purple(terminal.SymbolArrow),
			uaNote,
			terminal.Orange(strings.Join(hosts, ", "))))
	}

	// Record the outcome for the Discovery phase's low-yield auto-fuzz decision.
	r.spidering = spideringOutcome{
		ran:      true,
		records:  totalRecords,
		sawSSO:   len(ssoHosts) > 0,
		ssoHosts: ssoHosts,
	}

	if r.repository != nil && totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Spidering: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	completion := fmt.Sprintf("completed — %s records, %s states, %s actions in %s",
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Orange(fmt.Sprintf("%d", totalStates)),
		terminal.Orange(fmt.Sprintf("%d", totalActions)),
		terminal.HiPurple(fmtDuration(elapsed)))
	if skippedTargets > 0 {
		completion += fmt.Sprintf(" (%s targets skipped — phase budget ceiling of %s reached)",
			terminal.Yellow(fmt.Sprintf("%d", skippedTargets)),
			terminal.Yellow(fmtDuration(phaseCeiling)))
	}
	r.printPhaseComplete("Spidering", completion)
	return nil
}
