package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// freshenPerScanModules returns a copy of mods with per-scan-stateful active
// modules replaced by fresh instances. Those modules keep mutable state that is
// meaningful only within one scan (per-host dedup maps, per-scan budgets, compare
// clients, discovery maps), but the registry stores one shared singleton of each
// (GetActiveModules copies the pointers). Two concurrent server-mode scans sharing
// a singleton would race on / clobber that state and leak it across scans. Modules
// opt in by implementing modules.PerScanModule; swapping in their Fresh() instance
// for this scan's slice leaves the registry singleton untouched. Modules whose
// per-scan state is already isolated via dedup.Lazy(scanCtx.DedupMgr()) or
// ScanContext need not implement it.
func freshenPerScanModules(mods []modules.ActiveModule) []modules.ActiveModule {
	out := make([]modules.ActiveModule, len(mods))
	copy(out, mods)
	for i, mod := range out {
		if f, ok := mod.(modules.PerScanModule); ok {
			if fresh, ok := f.Fresh().(modules.ActiveModule); ok {
				out[i] = fresh
			}
		}
	}
	return out
}

// The module counts the dynamic-assessment phase records on its PhaseOutcome
// (Counts): how many modules it was handed, and how many distinct ones ran at
// least once across every round. The CLI's scan document reports them as
// modules{selected, executed}; a module whose CanProcess rejected every item,
// or a run whose baseline never answered, executes nothing.
const (
	CountModulesSelected = "modules_selected"
	CountModulesExecuted = "modules_executed"
)

// executedModules is the union, across a phase's executors, of the modules that
// ran at least once.
type executedModules map[string]struct{}

// note folds one executor's metrics in and records the running total on t.
func (s executedModules) note(t *phaseTracker, metrics map[string]stats.ModuleStatsSnapshot) {
	for id, m := range metrics {
		if m.Invocations > 0 {
			s[id] = struct{}{}
		}
	}
	t.setCount(CountModulesExecuted, int64(len(s)))
}

// runDynamicAssessmentPhase runs all modules on DB records with a feedback loop for newly discovered URLs.
func (r *Runner) runDynamicAssessmentPhase(ctx context.Context, infra *phaseInfra, activeModules []modules.ActiveModule, passiveModules []modules.PassiveModule) error {
	phaseStart := time.Now()

	if r.repository == nil {
		return fmt.Errorf("dynamic-assessment: database repository required")
	}

	r.printPhaseStart("DynamicAssessment", "execute dynamic security assessments through coordinated active and passive scanning modules")
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", len(activeModules))),
		terminal.Orange(fmt.Sprintf("%d", len(passiveModules))))
	// Count the extensions that were selected, not every one the engine loaded:
	// the module selection may have narrowed them (see filterExtensionModules).
	if n := countExtensionModules(activeModules, passiveModules); n > 0 {
		modulesLine += fmt.Sprintf(" (incl. %s extensions)",
			terminal.HiTeal(fmt.Sprintf("%d", n)))
	}
	r.printPhaseDetail(modulesLine)

	daSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if budget := PhaseSpeedDetail(r.settings, "dynamic-assessment", 0); budget != "" {
		daSpeedDetail += ", " + budget
	}
	r.printPhaseDetail(daSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))

	// Resolve feedback rounds early so we can show it in the phase header
	feedbackRounds := maxFeedbackRounds
	if r.settings != nil && r.settings.DynamicAssessment.MaxFeedbackRounds > 0 {
		feedbackRounds = r.settings.DynamicAssessment.MaxFeedbackRounds
	}
	r.printPhaseDetail(fmt.Sprintf("Feedback rounds: %s", terminal.HiBlue(fmt.Sprintf("%d", feedbackRounds))))
	if feedbackRounds <= 1 && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("increase feedback rounds to re-scan newly discovered URLs via"), terminal.HiCyan("vigolium config set dynamic-assessment.max_feedback_rounds 3"))
	}

	zap.L().Info("DynamicAssessment: running modules on database records",
		zap.Int("active", len(activeModules)),
		zap.Int("passive", len(passiveModules)))

	// Log quarantined hosts from prior phases so users see cross-phase propagation
	if infra.svc != nil && infra.svc.HostErrors != nil {
		if qc := infra.svc.HostErrors.QuarantinedCount(); qc > 0 {
			zap.L().Info("DynamicAssessment: carrying forward host errors from prior phases",
				zap.Int("quarantined_hosts", qc))
		}
	}

	// secret-detect stays in assessment even when the known-issue scan will run:
	// that phase is last, so dropping the module here lost all secret detection
	// whenever a scan was cut short. Record what this pass covers so the
	// known-issue secret batch scans only the records assessment never reached.
	if r.options.KnownIssueScanEnabled {
		r.secretCoverage = newSecretCoverage()
		passiveModules = wrapSecretCoverage(passiveModules, r.secretCoverage)
	}

	// Isolate per-scan-stateful modules from the shared registry singletons before
	// wiring or running them, so concurrent server-mode scans can't race on or
	// clobber each other's state (authz_compare's compare clients below, and
	// nextjs_chunk_audit's per-host discovery map).
	activeModules = freshenPerScanModules(activeModules)

	// modules{selected, executed} of the scan document; executed starts at 0 so
	// "nothing ran" is a stated zero rather than an absent count.
	executed := executedModules{}
	r.currentPhase.Load().setCount(CountModulesSelected, int64(len(activeModules)+len(passiveModules)))
	executed.note(r.currentPhase.Load(), nil)

	// The requester every module in this phase sends through. Under
	// session.use_in_discovery: false the primary session's credentials are
	// deliberately absent from infra.httpRequester (discovery and spidering must
	// stay anonymous) and arrive here instead, on a view that shares that
	// requester's pool, limiter and carried browser sessions. Derived ONCE for the
	// phase: a view per round or per module would split the response cache
	// partition and the connection pool for no gain.
	daRequester, err := r.assessmentRequester(infra)
	if err != nil {
		return fmt.Errorf("dynamic-assessment: %w", err)
	}

	// Configured authentication that never reached the scan means the assessment
	// is probing an authenticated app anonymously. Report it rather than let the
	// resulting 401s read as an application with nothing behind the login.
	if infra.authFailureReason != "" {
		r.printPhaseDetail(fmt.Sprintf("%s configured authentication could not be applied — assessment runs unauthenticated.",
			terminal.Yellow(terminal.SymbolWarning)))
		r.scanLogger.Warn("dynamic-assessment", "configured authentication could not be applied — assessment runs unauthenticated")
		tracker := r.currentPhase.Load()
		// auth_unavailable is always marked so a consumer has one code to look
		// for; the specific cause (cancelled, login_budget, …) rides alongside.
		// They coincide when the cause is an ordinary failure, and marking is
		// idempotent per code, so that case reports one reason.
		tracker.markPartial(database.ReasonAuthUnavailable)
		tracker.markPartial(infra.authFailureReason)
	}
	if len(infra.authUnverified) > 0 {
		r.currentPhase.Load().markPartial(database.ReasonAuthUnverified)
	}

	// Wire compare session clients into the authz-compare module
	if len(infra.compareSessions) > 0 {
		clients := make([]*http.Requester, len(infra.compareSessions))
		names := make([]string, len(infra.compareSessions))
		hostnames := make([]string, len(infra.compareSessions))
		for i, cs := range infra.compareSessions {
			clients[i] = cs.Client
			names[i] = cs.Name
			hostnames[i] = cs.Hostname
		}
		for _, mod := range activeModules {
			if ac, ok := mod.(*authz_compare.Module); ok {
				ac.SetCompareClients(clients, names, hostnames)
				break
			}
		}
	}

	// Update the top-level scan record with module info for cursor tracking.
	// The scan record was already created at the start of RunNativeScan().
	if _, err := r.repository.DB().NewUpdate().
		Model((*database.Scan)(nil)).
		Set("modules = ?", r.buildModulesString(activeModules, passiveModules)).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", infra.scanUUID).
		Exec(ctx); err != nil {
		zap.L().Warn("Failed to update scan modules", zap.Error(err))
	}

	// Resolve dynamic-assessment concurrency: scanning_pace.dynamic-assessment overrides global when CLI not explicit
	daConcurrency := r.phaseConcurrency("dynamic-assessment")

	// Browser confirmations (XSS dialog probes) launch their own Chrome from a
	// module that has no route back to the scan options; without these
	// defaults they went around --proxy entirely and ignored spidering.stealth.
	// Restored when the phase ends.
	defer spitolas.SetProbeDefaults(r.options.ProxyURL, r.probeStealth())()

	// OAST registration started with the infrastructure; collect it here with a
	// bounded wait. Unavailable OAST is reported once and the phase proceeds
	// without out-of-band checks (see awaitOAST).
	oastService := r.awaitOAST(ctx, infra)
	if oastService != nil {
		// Stop polling and deregister when the phase ends, as before;
		// infra.Close repeats it harmlessly.
		defer oastService.Close()
		r.printPhaseDetail(fmt.Sprintf("OAST: enabled via %s (out-of-band callback detection active)", oastService.ServerURL()))
		r.reportOASTMode(oastService)
	}

	// Compute in-scope origins (scheme/host/port) to filter DB records by CLI targets.
	// inScopeHostnames is derived for the hostname-only paths (finding dedup), which
	// carry no port column.
	inScopeHosts := r.getInScopeDBHosts(ctx)
	inScopeHostnames := database.HostnamesOf(inScopeHosts)

	// Shared insertion point cache across feedback rounds to avoid cold-start overhead
	ipCache := core.NewInsertionPointCache(4096)

	// Resolve per-phase settings from scanning pace config (static across rounds)
	// ResolvePhase owns every default here (parallel_passive is on for this
	// phase); with no settings, the built-in pace config supplies them.
	paceCfg := config.DefaultScanningPaceConfig()
	if r.settings != nil {
		paceCfg = &r.settings.ScanningPace
	}
	daPace := paceCfg.ResolvePhase("dynamic-assessment")
	daMaxDuration := daPace.MaxDuration
	daParallelPassive := daPace.ParallelPassive
	daFeedbackDrain := daPace.FeedbackDrainTimeout
	daActiveModuleTimeout := daPace.ActiveModuleTimeout

	// Enforce dynamic-assessment phase deadline across all feedback rounds. Without this wrap
	// each round's executor would start a fresh timeout, letting total phase time
	// reach feedbackRounds × daMaxDuration.
	var phaseCancel context.CancelFunc
	ctx, phaseCancel = r.trackedPhaseDeadline(ctx, daMaxDuration)
	defer phaseCancel()

	// Reset cursor so dynamic-assessment reads all records from the beginning
	// (seed phase advances the cursor past all records when saving them).
	// Skip reset for scan-on-receive — the cursor tracks which records have been scanned.
	if !r.options.ScanOnReceive {
		if err := r.repository.ResetScanCursor(ctx, infra.scanUUID); err != nil {
			zap.L().Warn("DynamicAssessment: failed to reset scan cursor", zap.Error(err))
		}
	}

	var recordWriter *database.RecordWriter
	var findingWriter *database.FindingWriter
	if r.repository != nil {
		recordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		// Batched, async finding persistence so module workers aren't blocked on
		// a synchronous SaveFinding round-trip.
		findingWriter = database.NewFindingWriter(r.repository, database.FindingWriterConfig{})
		// One deferred shutdown rather than two deferred Closes: findings drain
		// first (today's LIFO order, and the order the data depends on — a finding's
		// evidence is written through the record writer), and the two outcomes are
		// reported together instead of being discarded.
		defer func() {
			r.shutdownWriters("dynamic-assessment", findingWriter, recordWriter)
		}()
	}

	// phaseModuleTimeouts is shared across every per-round executor so the
	// timed-out total in the status line accumulates over the whole phase rather
	// than resetting each feedback round (Records/Findings are per-round by design).
	var phaseModuleTimeouts atomic.Int64

	// Shared across every per-round executor: a wall is a fact about the host,
	// not about the round that happened to hit it, so reporting per round would
	// repeat the same notice once per feedback round.
	authWalls := newAuthWallCollector()

	// One finding admission for the whole phase, for the same reason. Each round
	// gets a fresh executor, so executor-local admission reset the per-module cap
	// every round — a cap documented as holding for the remainder of the phase —
	// and let a root cause already reported in an earlier round re-fire every
	// callback and notification when the next round found it again.
	phaseAdmission := core.NewFindingAdmission()

	baseExecutorCfg := core.ExecutorConfig{
		OnModuleError: r.noteModuleError,
		Phase:         string(PhaseDynamicAssessment),
		Workers:       daConcurrency,
		Services:      infra.svc,
		// The authenticated view when use_in_discovery is false; otherwise
		// infra.httpRequester itself. See assessmentRequester.
		HTTPRequester: daRequester,
		Repository:    r.repository,
		RecordWriter:  recordWriter,
		FindingWriter: findingWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		// Subdomain feed-back is wired only here, on the dynamic-assessment phase —
		// the only phase that runs the full passive set with live feed-back. The
		// executor guard (FollowSubdomains && ScopeMatcher && !DisableFeedback) makes
		// it a no-op elsewhere, so subdomain_harvest stays recon-only in other phases.
		FollowSubdomains:     r.options.FollowSubdomains || strings.EqualFold(r.options.Intensity, "deep"),
		DeepScan:             strings.EqualFold(r.options.Intensity, "deep"),
		AllowRiskyPayloads:   r.riskyPayloadsAllowed(),
		NoParamDedup:         r.options.NoParamDedup,
		ModuleTimeouts:       &phaseModuleTimeouts,
		SkipBaseline:         true,
		PauseCtrl:            r.pauseCtrl,
		MaxFindingsPerModule: r.options.MaxFindingsPerModule,
		FindingAdmission:     phaseAdmission,
		TechFilterDisabled:   r.options.NoTechFilter || strings.EqualFold(r.options.Intensity, "deep"),
		// Seed the per-host content-class fallback from the heuristics root probe
		// so markup-only passive modules (clickjacking, autocomplete, SRI, mixed-
		// content) defer on confirmed JSON/XML API hosts even when a record lacks
		// its own Content-Type. Honors the same TechFilterDisabled switch.
		ContentClassByHost: r.contentClassByHostFromHeuristics(),
		OnTechDetected: func(host, tag string) {
			line := fmt.Sprintf("%s %s %s %s %s %s\n",
				terminal.PhasePrefix(string(PhaseDynamicAssessment)),
				terminal.BoldCyan("[tech-stack-detected]"),
				terminal.HiBlue(host),
				terminal.Muted("→"),
				terminal.Yellow(tag),
				terminal.Muted("(skips incompatible modules unless --no-tech-filter)"))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		},
		// Phase-level ctx already carries the dynamic-assessment deadline; leaving this at 0
		// prevents each feedback round from starting a fresh per-round timeout.
		MaxDuration:          0,
		ParallelPassive:      daParallelPassive,
		FeedbackDrainTimeout: daFeedbackDrain,
		ActiveModuleTimeout:  daActiveModuleTimeout,
		IPCache:              ipCache,
		OnTraffic:            r.makeOnTrafficVerbose("dynamic-assessment"),
		OnAuthWall:           authWalls.Observe,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
		OnStatus: func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			// CapturedConsole drops the periodic ticker — it's repetitive noise in a
			// captured per-target log file (the -P fan-out's child console.log).
			if r.options.Silent || r.options.CapturedConsole {
				return
			}
			prefix := terminal.Muted(terminal.SymbolChevron + " dynamic-assessment " + terminal.SymbolPipe)
			var recordsStr string
			if total > 0 {
				recordsStr = fmt.Sprintf("%d/%d", processed, total)
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}
			totalModules := activeCount + passiveCount
			// timedOut is phase-cumulative (shared across feedback rounds); the
			// helper appends it to the breakdown only when > 0.
			modulesStr := terminal.FormatModuleProgress(distinctModules, totalModules, activeCount, passiveCount, timedOut)
			fmt.Fprintf(os.Stderr, "%s %s Records: %s | Findings: %s | Modules: %s | Runtime: %s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)))
		},
		StatusInterval: 1 * time.Minute,
	}
	if oastService != nil {
		baseExecutorCfg.OASTProvider = oastService
		baseExecutorCfg.OASTService = oastService
	}
	if infra.hookChain != nil {
		baseExecutorCfg.Hooks = infra.hookChain
	}

	// Continuous scan-on-receive mode: use a polling DBInputSource that waits
	// indefinitely for new records instead of snapshot-based feedback rounds.
	if r.options.ScanOnReceive && !r.options.FullNativeScanOnReceive {
		sorCfg := baseExecutorCfg
		// scan-on-receive scans each ingested request exactly once with no
		// fan-out. Feedback is disabled so passive-module URL discoveries
		// (link extractors, redirect followers) don't persist new work items;
		// RecordWriter is nil so the executor doesn't write scanner-produced
		// rows that would get polled back into the scan. For targeted one-
		// request scans drive /api/scan-request directly.
		sorCfg.DisableFeedback = true
		sorCfg.RecordWriter = nil
		// In server mode the console stays terse (status line at a 2-minute cadence
		// is the only stderr output by default). The same events are always written
		// verbosely to runtime.log so operators can reconstruct activity after the
		// fact — see runner.writeSessionLog.
		// Fire the first status tick at 30s so users see progress quickly when
		// a scan kicks off, then fall back to the 2-minute cadence.
		sorCfg.StatusInterval = 2 * time.Minute
		sorCfg.FirstStatusInterval = 30 * time.Second
		origOnResult := sorCfg.OnResult
		sorCfg.OnTraffic = func(method, url string, statusCode int, contentType string) {
			line := formatTrafficLine("scan-on-receive", method, url, statusCode, contentType)
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		sorCfg.OnResult = func(result *output.ResultEvent) {
			if origOnResult != nil {
				origOnResult(result)
			}
			if result == nil {
				return
			}
			line := fmt.Sprintf("  %s %s [%s] %s — %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("finding"),
				terminal.Orange(result.Info.Severity.String()),
				terminal.BoldCyan(result.ModuleID),
				terminal.Gray(result.URL))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		shortScanID := strings.TrimPrefix(infra.scanUUID, "scan-")
		if len(shortScanID) > 8 {
			shortScanID = shortScanID[:8]
		}

		// Threshold for treating a fetch as a "resume from idle" event. Below
		// this, batches are considered back-to-back and we stay silent to avoid
		// spamming the console while the scan is steadily processing.
		const activityIdleThreshold = 5 * time.Second

		// Restrict the DB poller to records that came from user ingestion.
		// Without this, "finding" records persisted by the executor's
		// emitResult (pkg/core/executor_results.go — one row per finding with an
		// attached request/response pair) would get polled back into the
		// scan and fan out 1 ingested request → hundreds of re-scanned rows.
		sorSourceFilter := database.IngestRecordSources

		continuousSource := database.NewDBInputSource(r.repository.DB(), r.repository, infra.scanUUID, 2*time.Second).
			WithHostScopes(inScopeHosts).
			WithIncludeSources(sorSourceFilter).
			WithIdleTimeout(r.options.ScanOnReceiveIdleTimeout).
			WithOnActivity(func(records int, idleFor time.Duration, firstBatch bool) {
				// Print a one-line confirmation that the scan is actively processing
				// records. Two cases qualify: the very first batch ever (so the user
				// knows the scan started without waiting for the 2-min status tick),
				// or any batch that arrives after a quiet period.
				if !firstBatch && idleFor < activityIdleThreshold {
					return
				}
				prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
				var line string
				if firstBatch {
					line = fmt.Sprintf("%s %s scan-%s picked up %s — scanning started\n",
						prefix,
						terminal.BoldGreen("[start]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)))
				} else {
					line = fmt.Sprintf("%s %s scan-%s picked up %s after %s idle\n",
						prefix,
						terminal.BoldGreen("[resume]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)),
						terminal.Gray(fmtDuration(idleFor)))
				}
				r.writeSessionLog(line)
				// Always surface start/resume to stderr — even in server mode
				// where Silent is true — so the user sees confirmation that an
				// ingested request was picked up for scanning. Without this the
				// ingest HTTP log is the only signal, and the 2-min status tick
				// is too late.
				fmt.Fprint(os.Stderr, line)
			})

		// Forward-declared so OnStatus can query the executor's in-flight counter.
		// Assigned right before Execute() below.
		var sorExecutor *core.Executor

		// Threshold for showing the "idle Ns" suffix in the status line. We only
		// surface idle state once the source has been quiet for at least one poll
		// interval — otherwise the suffix would flicker on/off between ticks.
		const idleDisplayThreshold = 10 * time.Second

		// Tracks the ingested-record count at the previous status tick so we can
		// report the delta ("new ingested records" since last line). Accessed
		// only from the ticker goroutine, so no locking needed.
		var prevIngestedCount int64 = -1

		sorCfg.OnStatus = func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			// Use the phase context (captured from the enclosing function) so
			// these periodic status DB reads stop once the scan is cancelled
			// rather than outliving it on a detached context.Background().

			// Count HTTP records ingested since the scan started, scoped to the
			// in-scope hostnames if any were configured. Cheap enough at a
			// 2-minute cadence. Uses scan.StartedAt as the cursor reference.
			var ingestedCount int64 = -1
			var scanRow *database.Scan
			if r.repository != nil {
				if s, err := r.repository.GetScanByUUID(ctx, infra.scanUUID); err == nil && s != nil {
					scanRow = s
					// Count only user-ingested records so the "new ingested
					// records" counter matches what the DB poller will
					// actually scan (see sorSourceFilter above).
					if cnt, cErr := r.repository.CountRecordsAfterCursorBySource(ctx, r.options.ProjectUUID, s.StartedAt, "", sorSourceFilter, inScopeHosts); cErr == nil {
						ingestedCount = cnt
					}
				}
			}

			// Processed Records: X / Y (new ingested records: Z)
			//   X = records the executor has finished scanning
			//   Y = total records this scan has ever seen (ingested so far)
			//   Z = records that arrived since the previous status tick
			totalModules := activeCount + passiveCount
			var recordsStr string
			if ingestedCount >= 0 {
				delta := ingestedCount
				if prevIngestedCount >= 0 {
					delta = ingestedCount - prevIngestedCount
					if delta < 0 {
						delta = 0
					}
				}
				recordsStr = fmt.Sprintf("%d / %d (new ingested records: %d)",
					processed, ingestedCount, delta)
				prevIngestedCount = ingestedCount
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}

			// Modules: <scanned> / <total> — how many enabled modules have been
			// evaluated against any record so far, out of the full set. Counts
			// both modules that ran AND modules whose CanProcess rejected the
			// input shape (e.g., POST-only modules on a GET request) — so the
			// counter can reach parity with the total once every module has been
			// seen, instead of stalling on the "always-rejected" set forever.
			scannedModules := distinctModules
			if sorExecutor != nil {
				scannedModules = sorExecutor.ConsideredModuleCount()
			}
			modulesStr := terminal.FormatModuleCount(scannedModules, totalModules, timedOut)

			// Optional suffix: when no workers are in-flight and the source has
			// been quiet for a while, surface "idle <duration>" so the user knows
			// the scan is alive but waiting for new ingested records.
			var idleSuffix string
			inFlight := int64(0)
			if sorExecutor != nil {
				inFlight = sorExecutor.InFlight()
			}
			if inFlight == 0 {
				if idleFor := continuousSource.IdleFor(); idleFor >= idleDisplayThreshold {
					idleSuffix = " | " + terminal.Muted(fmt.Sprintf("idle %s", fmtDuration(idleFor)))
				}
			}

			prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
			fmt.Fprintf(os.Stderr, "%s %s %s Processed Records: %s | Findings: %s | Modules: %s | Runtime: %s%s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.Cyan("scan-"+shortScanID),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)),
				idleSuffix)
			if r.repository != nil && scanRow != nil {
				_ = r.repository.RefreshScanStats(ctx, infra.scanUUID)
			}
		}

		sorExecutor = core.NewExecutor(sorCfg, continuousSource, activeModules, passiveModules)
		executor := sorExecutor
		if oastService != nil {
			oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
		}
		_, err := executor.Execute(ctx)
		r.currentPhase.Load().noteExecution(executor.Report())
		if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
			executed.note(r.currentPhase.Load(), metrics)
			logModuleMetrics(metrics)
		}
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}

	// Stream findings to stderr as they're discovered so the phase shows live
	// results even when the stdout result stream is deferred to files (jsonl/
	// html) — otherwise only the periodic status heartbeat moves. No-op in
	// console mode (findings already print to stdout) or when silent, so the
	// wrap is installed only when stdout won't show them. Repeated-value findings
	// (one secret across many URLs) collapse to a single line via the same
	// grouper the post-phase dedup uses; the grouper persists across feedback
	// rounds so cross-round repeats also collapse.
	if !r.findingsVisibleOnStdout() {
		liveGrouper := newFindingGrouper(r.resolveFindingGrouping())
		baseOnResult := baseExecutorCfg.OnResult
		baseExecutorCfg.OnResult = func(result *output.ResultEvent) {
			if baseOnResult != nil {
				baseOnResult(result)
			}
			if result != nil && liveGrouper.observe(result) {
				r.echoLiveFinding("dynamic-assessment", result)
			}
		}
	}

	// Feedback loop: re-scan newly discovered URLs.
	//
	// roundsRun / roundErr / deadlineHit record HOW the loop ended, because the
	// completion line used to claim "all rounds completed" on every exit path
	// including a round that errored out — the one case where it was certainly
	// false. roundErr is returned at the end rather than swallowed: a round that
	// failed is a failed phase, and the scan continues past it exactly as it does
	// past any other non-fatal phase error.
	var (
		roundsRun   int
		roundErr    error
		deadlineHit bool
	)
	for round := 0; round < feedbackRounds; round++ {
		res, err := r.runDynamicAssessmentRound(ctx, infra, round, inScopeHosts, activeModules, passiveModules, baseExecutorCfg, oastService)
		roundsRun = round + 1
		executed.note(r.currentPhase.Load(), res.moduleMetrics)
		if err != nil {
			zap.L().Error("DynamicAssessment: executor error", zap.Error(err), zap.Int("round", round))
			roundErr = err
			break
		}
		// A checkpoint that did not land means the next round would re-read the
		// same resume cursor and re-serve the records this one just scanned. Stop
		// instead of burning the remaining rounds on repeated work; the phase is
		// already marked partial, so the shortfall is reported rather than hidden.
		if res.checkpointFailed {
			break
		}
		processed := res.processed

		// Deduplicate findings after each dynamic-assessment round, scoped to the
		// hosts being scanned. DA runs before known-issue-scan and only scans
		// in-scope hosts, so every finding present now is on one of these hosts —
		// host-scoping is coverage-equivalent here but avoids re-scanning the whole
		// project's findings table each round. Empty inScopeHostnames (no targets/
		// scope) falls back to a project-wide pass.
		r.deduplicateFindings(ctx, "DynamicAssessment", inScopeHostnames...)

		if ctx.Err() != nil {
			zap.L().Info("DynamicAssessment: phase deadline reached, stopping feedback loop",
				zap.Int("round", round+1), zap.Error(ctx.Err()))
			deadlineHit = true
			break
		}

		if round < feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHosts)
			if countErr != nil || newCount == 0 {
				if countErr != nil {
					zap.L().Debug("DynamicAssessment: failed to count remaining records", zap.Error(countErr))
				}
				break
			}
			r.printPhaseFeedback("DynamicAssessment",
				fmt.Sprintf("%s new records discovered, starting round %d", terminal.Orange(fmt.Sprintf("%d", newCount)), round+2))
			zap.L().Info("DynamicAssessment: new records discovered, starting next round",
				zap.Int64("new_records", newCount))
		}

		if processed == 0 {
			break
		}

		if round == feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHosts)
			if countErr == nil && newCount > 0 {
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Orange(fmt.Sprintf("%d", newCount)), terminal.Gray(fmt.Sprintf("new records discovered but skipped (max_feedback_rounds=%d)", feedbackRounds)))
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Gray("enable multi-round scanning via"), terminal.Cyan("vigolium config set dynamic-assessment.max_feedback_rounds 3"))
			}
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("DynamicAssessment", dynamicAssessmentExitLine(roundsRun, elapsed, roundErr, deadlineHit))
	r.reportAuthWalls("DynamicAssessment", authWalls)

	if roundErr != nil {
		r.currentPhase.Load().markPartial(database.ReasonRoundError)
		return fmt.Errorf("dynamic-assessment round %d: %w", roundsRun, roundErr)
	}
	return nil
}

// dynamicAssessmentExitLine describes how the feedback loop actually ended.
//
// It used to print "all rounds completed in …" unconditionally — on a round that
// errored, on a phase cut off at its deadline, and on a loop that stopped early
// because there was nothing left to scan. Three of the four cases were false, and
// the one an operator most needs to see (a failed round) was the most misleading.
func dynamicAssessmentExitLine(rounds int, elapsed time.Duration, roundErr error, deadlineHit bool) string {
	d := terminal.HiPurple(fmtDuration(elapsed))
	switch {
	case roundErr != nil:
		return fmt.Sprintf("stopped after round %d error in %s", rounds, d)
	case deadlineHit:
		return fmt.Sprintf("stopped at phase deadline after %d round(s) in %s", rounds, d)
	default:
		return fmt.Sprintf("completed %d round(s) in %s", rounds, d)
	}
}

func (r *Runner) runDynamicAssessmentRound(
	ctx context.Context,
	infra *phaseInfra,
	round int,
	inScopeHosts []database.HostTarget,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
	baseCfg core.ExecutorConfig,
	oastService *oast.Service,
) (daRoundResult, error) {
	var res daRoundResult
	roundStart := time.Now()
	dbSource := database.NewRiskPrioritizedDBInputSource(r.repository.DB(), r.repository, infra.scanUUID).
		WithHostScopes(inScopeHosts).
		WithParamShapeCoalescing(r.resolveMaxParamShapeSamples())

	executor := core.NewExecutor(baseCfg, dbSource, activeModules, passiveModules)
	if oastService != nil {
		oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
	}
	_, err := executor.Execute(ctx)
	tracker := r.currentPhase.Load()
	tracker.noteExecution(executor.Report())
	res.moduleMetrics = executor.ModuleMetrics()

	// Checkpoint the round's cursor, with a reported result.
	//
	// On a detached context with its own short budget: ctx is already expired on
	// the path that most needs this (a phase deadline, a Ctrl-C), and a checkpoint
	// that cannot be written is exactly the condition this exists to surface, so
	// running it on the dead context would guarantee the failure it is testing
	// for. WithoutCancel keeps the request values and drops the cancellation.
	flushCtx, flushCancel := context.WithTimeout(context.WithoutCancel(ctx), cursorFlushBudget)
	flushErr := dbSource.FlushCursor(flushCtx)
	flushCancel()
	if flushErr != nil {
		// The round's work is done but the cursor does not know it. Reporting the
		// phase as partial is what keeps the scan row from reading as a clean
		// predecessor — a later scan-on-receive run inherits a completed scan's
		// cursor, so a lying checkpoint under a clean verdict is how records get
		// skipped permanently rather than merely re-scanned.
		zap.L().Error("DynamicAssessment: failed to checkpoint the scan cursor; the round's records may be re-served",
			zap.Int("round", round+1), zap.Error(flushErr))
		r.scanLogger.Error("dynamic-assessment",
			fmt.Sprintf("round %d: scan cursor checkpoint failed: %s", round+1, flushErr))
		tracker.markPartial(database.ReasonCheckpointFailed)
		res.checkpointFailed = true
	}
	if unresolved := dbSource.Unresolved(); unresolved > 0 {
		zap.L().Warn("DynamicAssessment: round ended with records still unresolved; they stay behind the cursor and will be re-served",
			zap.Int("round", round+1), zap.Int("unresolved", unresolved))
	}

	if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
		logModuleMetrics(metrics)
	}
	if c := infra.httpRequester.Clusterer(); c != nil {
		c.LogStats()
	}
	infra.httpRequester.LogPoolStats()
	if err != nil {
		return res, err
	}

	processed := executor.Processed()
	res.processed = processed
	roundElapsed := time.Since(roundStart)
	// Surface how many redundant value-only-different records the param-shape
	// coalescing skipped this round, so the reduced item count isn't mistaken
	// for missing coverage (no silent caps).
	if dropped := dbSource.CoalescedDropped(); dropped > 0 {
		r.printPhaseFeedback("DynamicAssessment", fmt.Sprintf("coalesced %s same-shape records (kept up to %s value-distinct samples per endpoint shape: query, form, or JSON params)",
			terminal.Orange(fmt.Sprintf("%d", dropped)),
			terminal.Orange(fmt.Sprintf("%d", r.resolveMaxParamShapeSamples()))))
		r.scanLogger.Info("DynamicAssessment", fmt.Sprintf("param-shape coalescing skipped %d redundant records", dropped))
	}
	r.printPhaseComplete("DynamicAssessment",
		fmt.Sprintf("round %d — %s items in %s", round+1, terminal.Orange(fmt.Sprintf("%d", processed)), terminal.HiPurple(fmtDuration(roundElapsed))))
	fields := []zap.Field{
		zap.Int("round", round+1),
		zap.Int64("processed", processed),
	}
	// Surface how many candidate findings the body-differential safety net
	// dropped, so a quiet target is distinguishable from a confirmed-clean one.
	if suppressed := executor.SuppressedFindings(); suppressed > 0 {
		fields = append(fields, zap.Int64("findings_dropped_unconfirmed", suppressed))
	}
	zap.L().Info("DynamicAssessment: round completed", fields...)
	return res, nil
}

// daRoundResult is what one dynamic-assessment feedback round reports back to the
// loop that drives it.
//
// checkpointFailed is here rather than folded into the returned error because the
// two mean different things to the caller: an error ends the phase, while a
// failed checkpoint means the round's WORK succeeded and only its bookkeeping
// did not. The loop must stop either way — a cursor that did not advance makes
// the next round re-serve the same records forever — but a scan that produced
// findings should not be reported as a failed phase because one UPDATE lost a
// race with a locked database.
type daRoundResult struct {
	processed        int64
	checkpointFailed bool
	// moduleMetrics is the round executor's per-module tally, folded into the
	// phase's modules_executed count whether or not the round succeeded.
	moduleMetrics map[string]stats.ModuleStatsSnapshot
}

func (r *Runner) countRemainingDynamicAssessmentRecords(ctx context.Context, scanUUID string, hosts []database.HostTarget) (int64, error) {
	currentScan, err := r.repository.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		return 0, err
	}
	return r.repository.CountRecordsAfterCursor(ctx, r.options.ProjectUUID, currentScan.CursorAt, currentScan.CursorUUID, hosts...)
}

// waitForNewRecords polls until at least one record exists after the scan cursor,
// or the context is cancelled. Used by full-native-scan-on-receive to block between iterations.
func (r *Runner) waitForNewRecords(ctx context.Context, scanUUID string, pollInterval time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		count, err := r.countRemainingDynamicAssessmentRecords(ctx, scanUUID, nil)
		if err != nil {
			zap.L().Debug("waitForNewRecords: query error", zap.Error(err))
		}
		if count > 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
