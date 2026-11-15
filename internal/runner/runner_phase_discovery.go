package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// discoveryEgress is the deparos egress hook for one discovery phase run: the
// scan's host slots and quarantine (through its egress gate), with discovery's
// own pace — discovery.rate_limit or an explicit --rate-limit, unpaced
// otherwise (config.DiscoveryRateLimit) — as ONE token bucket shared by every
// concurrent discovery target. Built once per phase run, so the rate is
// phase-wide rather than per target.
func discoveryEgress(infra *phaseInfra, rateLimit int) func(nethttp.RoundTripper) nethttp.RoundTripper {
	var svc *services.Services
	if infra != nil {
		svc = infra.svc
	}
	gate := svc.EgressGate().WithRate(buildScanRateLimiter(rateLimit))
	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		// The feedback variant: discovery reports every response to the host
		// limiter as the scan Requester does, so a throttling or WAF-blocking
		// host backs off and a host pre-armed by preflight can recover.
		return gate.FeedbackRoundTripper(next, egress.LaneNormal, wafBlockClassifier{})
	}
}

// wafBlockClassifier is the scan Requester's WAF block classification
// (deparos/waf), shaped for egress.FeedbackRoundTripper.
type wafBlockClassifier struct{}

func (wafBlockClassifier) IsBlockStatus(status int) bool { return waf.IsBlockStatusCode(status) }

func (wafBlockClassifier) IsBlock(status int, header nethttp.Header, body []byte) bool {
	return waf.ClassifyParts(status, header, body) != nil
}

func (r *Runner) runDiscoveryPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	// phaseCtx owns everything this phase starts: the deparos producer goroutine,
	// the concurrent-source readers and the executor. Cancelling it after Execute
	// returns is what stops the producer from burning the rest of a target's
	// MaxDuration on work nobody will read. ctx itself stays live for the
	// post-phase bookkeeping below.
	phaseCtx, phaseCancel := context.WithCancel(ctx)
	defer phaseCancel()

	// Discovery wordlists may not spend the whole --max-requests budget before
	// the assessment runs: cap the phase at its request share.
	defer r.requestBudget.LimitPhase(string(PhaseDiscovery), r.discoveryRequestShare())()

	var sources []source.InputSource
	var discoveryTargets []string
	discoveryDeadline := false

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
	var wls resolvedDiscoveryWordlists
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
		wls = r.resolveDiscoveryWordlists()
		deparosCfg := r.buildDeparosConfig(additionalTargets, wls)
		// The egress seam. Deparos has its own HTTP client, so the executor's scope
		// check (which runs on records it has already fetched) could only ever
		// discard an excluded host's response AFTER contacting it. An explicit
		// exclusion is a request not to contact it, so it is enforced here: the
		// engine refuses the request before sending, and never queues the link.
		//
		// Explicit denials only — see ScopeMatcher.ExplicitlyExcluded and triage
		// C12. Include lists and origin mode stay with ScopeMode, which already
		// decides how wide the crawl goes.
		if matcher := infra.scopeMatcher; matcher != nil {
			deparosCfg.RequestFilter = func(u *neturl.URL) bool {
				if u == nil {
					return true
				}
				return !matcher.ExplicitlyExcluded(u.Hostname(), u.Path)
			}
		}
		if pol := r.options.TrafficPolicy; pol != nil {
			deparosCfg.MethodFilter = pol.AllowsMethod
		}
		// Forms follow the browser's submit_forms decision: when the
		// crawl may not submit, discovery keeps forms as metadata-only stubs.
		if r.settings != nil {
			bp := resolveBrowserPolicy(r.settings.Spidering, r.options.Intensity)
			bp.applyTrafficPolicy(r.options.TrafficPolicy)
			if !bp.policy.SubmitForms {
				deparosCfg.FormSafety = "metadata-only"
			}
		}
		deparosCfg.Egress = discoveryEgress(infra, deparosCfg.RateLimit)
		// Phase ceiling (discovery.phase_max_duration): every target keeps its
		// own budget, but the phase as a whole is bounded too.
		if d := r.discoveryPhaseMaxDuration(len(discoveryTargets)); d > 0 {
			var deadlineCancel context.CancelFunc
			phaseCtx, deadlineCancel = context.WithTimeout(phaseCtx, d)
			defer deadlineCancel()
			discoveryDeadline = true
			zap.L().Info("Discovery: phase ceiling", zap.Duration("max", d), zap.Int("targets", len(discoveryTargets)))
		}
		src, srcErr := source.NewDeparosDiscoverySource(phaseCtx, deparosCfg)
		if srcErr != nil {
			zap.L().Warn("Failed to initialize deparos discovery", zap.Error(srcErr))
		} else {
			discoverSrc = src
			sources = append(sources, discoverSrc)
			// Deparos' traffic does not pass through the shared requester, so without
			// this the phase reported ≈0 requests for the crawl that produced every
			// record it emitted.
			r.currentPhase.Load().addCounter(discoverSrc.RequestsSent)
		}
	} else {
		discoveryTargets = r.options.Targets
	}

	sources = append(sources, r.inputSource)

	var compositeSource source.InputSource
	if len(sources) == 1 {
		compositeSource = sources[0]
	} else {
		compositeSource = source.NewConcurrentMultiSource(phaseCtx, sources...)
	}

	r.printPhaseStart("Discovery", "ingest inputs and discover directories, files, and hidden endpoints via Deparos content discovery")

	// Only the dials discovery actually applies (config.phasePaceSupport): the
	// engine's thread count, its brute-force (wordlist/FUZZ) worker count per
	// target, its wire protocol policy and, when one is explicitly configured,
	// its request rate (one bucket for the whole phase). Its host slots are the scan's own
	// (the shared host limiter, through the egress gate), so no discovery-specific
	// max-per-host is printed; the concurrency printed is the section's.
	rateDetail := "unlimited"
	if rate := r.discoveryRateLimit(); rate > 0 {
		rateDetail = fmt.Sprintf("%d/s", rate)
	}
	bruteForce, protocol := r.discoveryWirePace(r.discoveryConcurrency())
	speedDetail := fmt.Sprintf("Speed: threads=%s, brute-force=%s, rate-limit=%s, protocol=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.discoveryConcurrency())),
		terminal.HiBlue(fmt.Sprintf("%d", bruteForce)),
		terminal.HiBlue(rateDetail),
		terminal.HiBlue(protocol))
	// The option is what buildDeparosConfig hands the phase, so it is what gets
	// reported.
	if budget := PhaseSpeedDetail(r.settings, "discovery", r.options.DiscoverMaxDuration); budget != "" {
		speedDetail += ", " + budget
	}
	r.printPhaseDetail(speedDetail)

	// Content-discovery status: whether deparos runs this phase (vs. plain input
	// ingestion), the dictionary wordlists feeding it, and whether FUZZ fuzzing is
	// on — each on its own line. Shown unconditionally because "is this scan
	// discovering/fuzzing, and with what" is the first thing operators ask of the
	// Discovery phase.
	r.printDiscoveryStatusLines(discoverSrc != nil, wls)

	if r.autoFuzzDiscovery && !r.options.Silent {
		reason := fmt.Sprintf("spidering found little content (%d records)", r.spidering.records)
		if !r.spidering.complete {
			reason = fmt.Sprintf("spidering kept little content (%d records; capture incomplete, %d lost)",
				r.spidering.records, r.spidering.lost)
		}
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

	// The "turn fuzzing on" tip is for a run that simply didn't ask for it. Under
	// --no-discovery-fuzz the operator asked for the opposite, and a tip telling
	// them how to enable what they just disabled reads as the flag not working.
	if fuzzEnabled, _ := r.discoveryFuzzingState(); !fuzzEnabled && !r.options.NoDiscoveryFuzz && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enable on-the-fly directory fuzzing with a custom wordlist via"), terminal.HiCyan("--discovery-wordlist <path>"))
	}

	enrichTargetsEnabled := false
	if r.settings != nil {
		enrichTargetsEnabled = r.settings.Discovery.EnrichTargets
	}
	if !enrichTargetsEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich discovery targets with discovered paths via"), terminal.HiCyan("vigolium config set discovery.enrich_targets true"))
	}

	zap.L().Info("Discovery: ingesting input into database")

	var discoveryRecordWriter *database.RecordWriter
	if r.repository != nil {
		discoveryRecordWriter = r.newScanRecordWriter()
	}

	authWalls := newAuthWallCollector()

	executorCfg := core.ExecutorConfig{
		OnModuleError: r.noteModuleError,
		Phase:         string(PhaseDiscovery),
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  discoveryRecordWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("discovery"),
		// Deparos' own client never follows a redirect, so this fires only for
		// the items that reach fetchBaseline: CLI targets and request-only
		// spec-endpoint stubs. Those are precisely the entry points most likely
		// to be gated.
		OnAuthWall:     authWalls.Observe,
		OnRecordStored: r.onRecordStored(),
		// Deparos already captured a response for each crawled URL and emits it on
		// the work item (deparos_discovery.go saveAndEmit); reuse it instead of
		// issuing a second identical request per URL. Request-only items (spec-
		// endpoint stubs, which carry no response) still fall through to a single
		// baseline fetch in fetchBaseline, so routes aren't left empty.
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
	_, err := executor.Execute(phaseCtx)
	if discoveryDeadline && ctx.Err() == nil && errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
		if tr := r.currentPhase.Load(); tr != nil {
			tr.markPartial(database.ReasonPhaseDeadline)
		}
	}
	r.currentPhase.Load().noteExecution(executor.Report())

	// Shut down in producer-then-writer order: phaseCancel stops the deparos
	// engine and the concurrent readers, Close joins the producer so the records
	// it already collected are persisted (bounded by DrainTimeout), and only then
	// is the record writer drained — it is what those records are written through.
	//
	// compositeSource is deliberately NOT closed: when more than one source was
	// merged it wraps r.inputSource, whose lifetime belongs to releaseResources,
	// and closing it here would tear down an input later phases still read.
	phaseCancel()
	if discoverSrc != nil {
		if closeErr := discoverSrc.Close(); closeErr != nil {
			zap.L().Warn("Discovery: failed to close deparos source", zap.Error(closeErr))
		}
	}
	r.shutdownWriters("discovery", discoveryRecordWriter)
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
	r.reportAuthWalls("Discovery", authWalls)
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
		if stats.JSFactsPersisted > 0 {
			withheld := 0
			for _, n := range stats.JSFactsWithheld {
				withheld += n
			}
			r.printPhaseFeedback("Discovery", fmt.Sprintf(
				"stored %s JS-derived request(s) the crawl did not confirm (%s not found, %s never sent) as source=jstangle",
				terminal.Orange(fmt.Sprintf("%d", stats.JSFactsPersisted)),
				terminal.HiTeal(fmt.Sprintf("%d", stats.JSFactsNotFound)),
				terminal.HiTeal(fmt.Sprintf("%d", withheld))))
		}
		r.reportDiscoveryCoverage(stats)
	}

	return nil
}

// reportDiscoveryCoverage reports what the phase did NOT get to, on both
// channels: an operator-facing stderr line, and a structured reason on the
// phase's outcome.
//
// Discovery used to log per-target failures at warn level and move on, so a run
// where every target errored, timed out, or was cancelled before it started
// looked exactly like a run that honestly found nothing. Both channels carry it
// because they answer different questions: the stderr line tells the operator
// watching the scan, the reason tells the scan row and the event stream — and a
// driver reading `--events` has no stderr to scrape.
//
// Timed-out targets are a LIMIT, not a reason: a per-target time box doing its
// job is configured behaviour, and marking it as degraded coverage would flag
// every properly bounded discovery run.
func (r *Runner) reportDiscoveryCoverage(stats source.DiscoveryStats) {
	tracker := r.currentPhase.Load()

	if stats.TargetsFailed > 0 {
		msg := fmt.Sprintf("%s target(s) failed discovery",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsFailed)))
		if len(stats.TargetErrors) > 0 {
			msg += " — " + terminal.Gray(stats.TargetErrors[0])
		}
		r.printPhaseFeedback("Discovery", msg)
		tracker.markPartial(database.ReasonTargetsFailed)
	}
	if stats.TargetsTimedOut > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s target(s) hit their discovery time budget — coverage is partial",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsTimedOut))))
		tracker.noteLimit(database.LimitTargetBudget)
	}
	if stats.TargetsSkipped > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s target(s) never attempted — the phase stopped first",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsSkipped))))
		tracker.markPartial(database.ReasonTargetsSkipped)
	}
	if stats.ImportFailed > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s discovered record(s) could not be stored",
			terminal.Orange(fmt.Sprintf("%d", stats.ImportFailed))))
		tracker.markPartial(database.ReasonPersistence)
	}
	if stats.JSTemplatesCapped > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s JS-derived request template(s) not stored — per-target cap reached (discovery.jstangle.max_persisted_js_templates)",
			terminal.Orange(fmt.Sprintf("%d", stats.JSTemplatesCapped))))
		tracker.noteLimit(database.LimitJSTemplatePersistCap)
	}
	if stats.SitemapCapped > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s sitemap URL(s) not spidered — sitemap budget reached (discovery.sitemap.max_urls)",
			terminal.Orange(fmt.Sprintf("%d", stats.SitemapCapped))))
		tracker.noteLimit(database.LimitSitemapCap)
	}
	if stats.Abandoned {
		r.printPhaseFeedback("Discovery", terminal.Orange(
			"the discovery producer did not exit in time and was abandoned; some discovered records may be missing"))
		tracker.markPartial(database.ReasonProducerAbandoned)
	}
}

// printDiscoveryStatusLines prints the Discovery phase's content-discovery status
// and, when deparos is active, its wordlist and fuzzing lines as separate detail
// rows. deparosActive mirrors the runDiscoveryPhase gate (DiscoverEnabled &&
// targets present && source init succeeded); wls is the phase's resolved
// wordlists, read only when deparos is active.
func (r *Runner) printDiscoveryStatusLines(deparosActive bool, wls resolvedDiscoveryWordlists) {
	if !deparosActive {
		r.printPhaseDetail(fmt.Sprintf("Content discovery: %s — %s",
			terminal.Orange("disabled"), terminal.Gray(r.discoveryDisabledReason())))
		return
	}
	r.printPhaseDetail(fmt.Sprintf("Content discovery: %s (deparos)", terminal.HiTeal("enabled")))
	r.printPhaseDetail("Wordlists: " + r.discoveryWordlistSummary(wls))
	r.printPhaseDetail("Fuzzing: " + r.discoveryFuzzingSummary(wls))
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
func (r *Runner) discoveryWordlistSummary(w resolvedDiscoveryWordlists) string {
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
			label += " " + terminal.Gray("(incl. embedded defaults, "+w.tier+" tier)")
		case anyEmbedded:
			label += " " + terminal.Gray("(embedded defaults, "+w.tier+" tier)")
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
func (r *Runner) discoveryFuzzingSummary(w resolvedDiscoveryWordlists) string {
	enabled, reason := r.discoveryFuzzingState()
	if !enabled {
		return fmt.Sprintf("%s — %s", terminal.Orange("disabled"), terminal.Gray(reason))
	}

	src := "embedded default"
	if len(r.options.FuzzWordlistPaths) > 0 {
		src = "via --discovery-wordlist"
	}
	list := terminal.HiTeal("fuzz.txt")
	if len(w.fuzz) > 0 {
		entries := make([]string, 0, len(w.fuzz))
		for _, p := range w.fuzz {
			entries = append(entries, formatWordlistEntry(p))
		}
		list = strings.Join(entries, ", ")
	}
	return fmt.Sprintf("%s — %s (%s), appends /FUZZ %s",
		terminal.HiTeal("enabled"),
		list,
		terminal.Gray(src),
		terminal.Gray("["+reason+"]"))
}

// cleanupDeparosRecords runs the post-discovery record-dedup passes over the full
// stored set (the in-engine hard dedup only sees one target at a time):
//
//  1. status-retention policy — drop 4xx discovery rejections (a fuzzed path the
//     server answers with a client error is not a discovered resource), keeping a
//     single representative per host for "auth wall exists" statuses;
//  2. reflected-URL-robust dedup — collapse records that differ only by an echoed
//     request URL/path or per-request dynamic tokens (the error-page-mirrors-the-URI
//     case that defeats exact-hash dedup);
//  3. shape-based soft-dedup backstop.
//
// (1) and (2) are config-gated (Discovery.DeparosDedup); (3) always runs,
// preserving prior behavior. Each pass emits one feedback line when it removes
// anything.
func (r *Runner) cleanupDeparosRecords(ctx context.Context) {
	report := func(label string, res database.RecordCleanupResult) {
		if res.Deleted <= 0 && res.KeptReferenced <= 0 {
			return
		}
		detail := fmt.Sprintf("%s %s records", label, terminal.Orange(fmt.Sprintf("%d", res.Deleted)))
		if len(res.ByStatus) > 0 {
			detail += " — " + formatStatusCodeMap(res.ByStatus)
		}
		// Say when a pass spared evidence, so a smaller-than-expected deletion
		// count does not read as the pass having failed.
		if res.KeptReferenced > 0 {
			detail += fmt.Sprintf(" (kept %d referenced by findings)", res.KeptReferenced)
		}
		r.printPhaseFeedback("Discovery", detail)
		r.scanLogger.Info("discovery", fmt.Sprintf("%s %d records (kept %d referenced)", label, res.Deleted, res.KeptReferenced))
	}

	// Refresh query-planner statistics before the dedup window queries run:
	// discovery just bulk-inserted thousands of records, and without fresh stats
	// SQLite plans the PARTITION-BY dedup scans against default row guesses.
	if r.repository != nil && r.repository.DB() != nil {
		r.repository.DB().Optimize(ctx)
	}

	if r.settings != nil && r.settings.Discovery.DeparosDedup.IsEnabled() {
		dedupCfg := &r.settings.Discovery.DeparosDedup
		if dedupCfg.DropClientErrorsEnabled() {
			statusPolicy := database.DeparosStatusPolicy{
				KeepOnePerHost: dedupCfg.KeepOneStatuses(),
				KeepPerPath:    dedupCfg.KeepPerPathStatuses(),
				PerPathCap:     dedupCfg.PerPathCapValue(),
				AuthWallCap:    dedupCfg.AuthWallCapValue(),
			}
			res, err := r.repository.ApplyDeparosStatusPolicy(ctx, r.options.ProjectUUID, statusPolicy)
			if err != nil {
				zap.L().Warn("Deparos status-policy cleanup failed", zap.Error(err))
			} else {
				report("dropped client-error", res)
			}
		}
		if dedupCfg.NormalizeReflectedEnabled() {
			// Per-path statuses keep their distinct paths (and are capped by
			// the status policy), so the reflected-URL collapse skips them.
			var keepPerPath []int
			if dedupCfg.DropClientErrorsEnabled() {
				keepPerPath = dedupCfg.KeepPerPathStatuses()
			}
			res, err := r.repository.DeduplicateDeparosByNormHash(ctx, r.options.ProjectUUID, keepPerPath...)
			if err != nil {
				zap.L().Warn("Deparos reflected-URL dedup failed", zap.Error(err))
			} else {
				report("collapsed reflected-URL", res)
			}
		}
	}

	softRes, err := r.repository.DeduplicateSoftDeparosRecords(ctx, r.options.ProjectUUID)
	if err != nil {
		zap.L().Warn("Deparos soft deduplication failed", zap.Error(err))
	} else {
		report("soft-deduplicated", softRes)
	}
}

// discoveryPhaseMaxDuration resolves the discovery phase ceiling from
// discovery.phase_max_duration (default --discover-max-time × min(targets, 3)).
func (r *Runner) discoveryPhaseMaxDuration(targets int) time.Duration {
	if r.settings == nil {
		var dc config.DiscoveryConfig
		return dc.PhaseMaxDurationValue(r.options.DiscoverMaxDuration, targets)
	}
	return r.settings.Discovery.PhaseMaxDurationValue(r.options.DiscoverMaxDuration, targets)
}
