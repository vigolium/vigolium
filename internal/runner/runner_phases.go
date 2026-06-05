package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// RunNativeScan orchestrates the native scan plan:
//
//	HeuristicsCheck   — optional root-page probe to optimize downstream phase selection
//	ExternalHarvest   — harvest URLs from external intelligence sources (opt-in)
//	Spidering         — browser-based crawling (opt-in)
//	Discovery         — ingest all input + deparos content discovery into DB (no modules)
//	Seed              — ingest CLI targets when discovery is skipped but DB-backed phases still need records
//	KnownIssueScan    — nuclei + kingfisher batch (opt-in via --known-issue-scan)
//	DynamicAssessment — modules + extensions scan DB records
func (r *Runner) RunNativeScan() error {
	defer close(r.done)
	ctx := r.ctx

	// Total scan budget: when --scanning-max-duration is set, bound the WHOLE scan
	// (all phases combined). Each phase wraps this ctx with its own per-phase
	// deadline via phaseDeadline, which keeps the earlier deadline — so phases can
	// share and never exceed this total budget. End-of-scan DB bookkeeping below
	// stays on r.ctx (the un-bounded parent) so the scan record is still finalized
	// after the budget fires.
	if r.options.ScanMaxDuration > 0 {
		zap.L().Info("Total scan budget active — the whole scan is bounded by --scanning-max-duration; phases share it and remaining phases are skipped once it elapses",
			zap.Duration("scan_max_duration", r.options.ScanMaxDuration))
		var totalCancel context.CancelFunc
		ctx, totalCancel = context.WithTimeout(ctx, r.options.ScanMaxDuration)
		defer totalCancel()
	}

	infra, err := r.buildInfrastructure()
	if err != nil {
		return err
	}
	defer infra.Close()

	// Initialize scan logger (must happen before printScanConfig so the tee captures it)
	r.scanLogger = database.NewScanLogger(r.repository, infra.scanUUID)
	r.scanLogger.StartBatcher()
	defer r.scanLogger.Close()

	// Create scan record in the database so every scan is tracked with its lifecycle.
	// Skip when ScanOnReceive — the server already created the scan record.
	if r.repository != nil && !r.options.ScanOnReceive {
		target := strings.Join(r.options.Targets, ", ")
		scan := &database.Scan{
			UUID:        infra.scanUUID,
			ProjectUUID: r.options.ProjectUUID,
			Name:        "cli-scan",
			Status:      "running",
			Target:      target,
			Threads:     r.options.Concurrency,
			ScanSource:  "cli",
			ScanMode:    "full",
			StartedAt:   time.Now(),
		}
		if err := r.repository.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}
	if r.repository != nil {
		defer func() {
			var errMsg string
			if r.ctx.Err() != nil {
				errMsg = "cancelled"
			}
			// Write on r.ctx (un-bounded parent), not the total-budget-bounded ctx:
			// a scan curtailed by --scanning-max-duration must still record completion.
			if completeErr := r.repository.CompleteScan(r.ctx, infra.scanUUID, errMsg); completeErr != nil {
				zap.L().Warn("Failed to complete scan record", zap.Error(completeErr))
			}
		}()
	}

	// Set up TeeWriter to capture raw stderr output as trace-level scan logs.
	if r.repository != nil {
		origStderr := os.Stderr
		// Optionally mirror raw console output to ~/.vigolium/native-sessions/{uuid}/run.log.
		var sessionLogFile *os.File
		var teeInner io.Writer = origStderr
		if r.settings != nil && r.settings.ScanningStrategy.ScanLogs.IsPersistLogsEnabled() {
			sessionDir := filepath.Join(r.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), infra.scanUUID)
			if mkErr := os.MkdirAll(sessionDir, 0o755); mkErr == nil {
				logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
				if f, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); openErr == nil {
					sessionLogFile = f
					r.sessionLogFile = f
					teeInner = io.MultiWriter(origStderr, sessionLogFile)
				} else {
					zap.L().Warn("Failed to open native session log file", zap.String("path", logPath), zap.Error(openErr))
				}
			} else {
				zap.L().Warn("Failed to create native session directory", zap.String("path", sessionDir), zap.Error(mkErr))
			}
		}
		r.teeWriter = newTeeWriter(teeInner, r.scanLogger)
		pr, pw, err := os.Pipe()
		if err == nil {
			os.Stderr = pw
			// Goroutine reads from the pipe and writes through the tee.
			go func() {
				buf := make([]byte, 4096)
				for {
					n, readErr := pr.Read(buf)
					if n > 0 {
						_, _ = r.teeWriter.Write(buf[:n])
					}
					if readErr != nil {
						break
					}
				}
			}()
			defer func() {
				_ = pw.Close()
				// Allow goroutine to drain.
				time.Sleep(50 * time.Millisecond)
				_ = pr.Close()
				os.Stderr = origStderr
				r.teeWriter.Flush()
				if sessionLogFile != nil {
					r.sessionLogMu.Lock()
					r.sessionLogFile = nil
					r.sessionLogMu.Unlock()
					_ = sessionLogFile.Close()
				}
			}()
		} else if sessionLogFile != nil {
			// Pipe setup failed; still close the log file we opened.
			defer func() { _ = sessionLogFile.Close() }()
		}
	}

	// Print scan configuration summary
	r.printScanConfig()

	r.scanLogger.Info("", "scan started")

	// Log scan configuration snapshot as structured metadata.
	r.logConfigSnapshot()

	// Banner the end of the scan lifecycle on stderr so operators see at a glance
	// when scanning wraps up, with wall-clock duration and finding count.
	// Suppressed by --silent. The scan kickoff is already announced by the Scan ID
	// line in the configuration banner above, so there is no separate "started"
	// marker here.
	scanStartedAt := time.Now()
	if !r.options.Silent {
		defer func() {
			duration := time.Since(scanStartedAt)
			findingSummary := ""
			if r.repository != nil {
				// Use the run context (consistent with the CompleteScan defer
				// above) so this terminal summary read participates in
				// cancellation instead of running on a detached Background.
				if scan, err := r.repository.GetScanByUUID(ctx, infra.scanUUID); err == nil && scan != nil {
					findingSummary = fmt.Sprintf(", findings: %d", scan.TotalFindings)
				}
			}
			fmt.Fprintf(os.Stderr, "  %s Scan finished %s %s\n",
				terminal.SuccessSymbol(),
				terminal.BoldCyan(infra.scanUUID),
				terminal.Gray(fmt.Sprintf("duration: %s%s", fmtDuration(duration), findingSummary)))
		}()
	}

	// Panic recovery with notification
	defer func() {
		if rec := recover(); rec != nil {
			stack := make([]byte, 4096)
			length := goruntime.Stack(stack, false)
			stackTrace := string(stack[:length])

			errorMessage := fmt.Sprintf(
				"Recovered from panic in runner execution: %+v\nStack Trace:\n%s",
				rec,
				stackTrace,
			)
			zap.L().Error(errorMessage)
			r.scanLogger.Error("", "panic recovered: "+fmt.Sprintf("%+v", rec))
			if infra.notifier != nil {
				_ = infra.notifier.SendRaw(errorMessage)
			}
		}
	}()

	plan := BuildNativeScanPlan(r.options)

	// Full-scan-on-receive: loop waiting for new records, then run all phases
	// on just the new batch. Each iteration swaps r.inputSource to a one-shot
	// DB source so Discovery processes only newly arrived records.
	if r.options.FullNativeScanOnReceive && r.repository != nil {
		for ctx.Err() == nil {
			if err := r.waitForNewRecords(ctx, infra.scanUUID, 2*time.Second); err != nil {
				break
			}
			r.inputSource = database.NewOneShotDBInputSource(r.repository.DB(), r.repository, infra.scanUUID)
			for _, step := range plan.Steps {
				if !step.Enabled {
					continue
				}
				if ctx.Err() != nil {
					break
				}
				if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
					zap.L().Error("Full-scan-on-receive: phase error", zap.Error(err))
					break
				}
			}
		}
		r.scanLogger.Info("", "scan finished")
		return nil
	}

	for _, step := range plan.Steps {
		if !step.Enabled {
			continue
		}
		// Stop launching phases once the total scan budget (--scanning-max-duration)
		// has elapsed. Mirrors the full-scan-on-receive loop guard above so a
		// curtailed scan ends cleanly instead of starting phases that would
		// immediately abort on the already-expired ctx.
		if ctx.Err() != nil {
			zap.L().Warn("Scan budget (scanning-max-duration) reached; skipping remaining phases",
				zap.String("phase", string(step.Phase)))
			break
		}
		if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
			return err
		}
	}
	if r.options.SkipIngestion && !r.options.KnownIssueScanEnabled && r.options.SkipDynamicAssessment {
		zap.L().Info("Discovery skipped, no downstream phases need DB records")
		r.scanLogger.Info("discovery", "skipped, no downstream phases need DB records")
	}
	if r.options.SkipDynamicAssessment {
		zap.L().Info("Dynamic-assessment skipped by scanning strategy")
		r.scanLogger.Info("dynamic-assessment", "skipped by scanning strategy")
	}

	r.scanLogger.Info("", "scan finished")
	return nil
}

func (r *Runner) executeNativePhase(ctx context.Context, infra *phaseInfra, phase NativePhase) error {
	switch phase {
	case PhaseHeuristicsCheck:
		r.setPhaseTag("heuristics")
		r.scanLogger.Info("heuristics", "phase started")
		results, err := r.runHeuristicsCheckPhase(ctx, infra)
		if err != nil {
			zap.L().Error("HeuristicsCheck phase failed", zap.Error(err))
			r.scanLogger.Error("heuristics", "phase failed: "+err.Error())
		} else {
			r.heuristicsResults = results
			r.scanLogger.Info("heuristics", "phase completed")
		}
	case PhaseExternalHarvest:
		r.setPhaseTag("harvest")
		r.scanLogger.Info("harvest", "phase started")
		if err := r.runExternalHarvestPhase(ctx, infra); err != nil {
			zap.L().Error("ExternalHarvest phase failed", zap.Error(err))
			r.scanLogger.Error("harvest", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("harvest", "phase completed")
		}
	case PhaseSpidering:
		r.setPhaseTag("spider")
		r.scanLogger.Info("spidering", "phase started")
		if err := r.runSpideringPhase(ctx, infra); err != nil {
			zap.L().Error("Spidering phase failed", zap.Error(err))
			r.scanLogger.Error("spidering", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("spidering", "phase completed")
		}
	case PhaseDiscovery:
		r.setPhaseTag("discovery")
		r.scanLogger.Info("discovery", "phase started")
		if err := r.runDiscoveryPhase(ctx, infra); err != nil {
			r.scanLogger.Error("discovery", "phase failed: "+err.Error())
			return fmt.Errorf("discovery phase failed: %w", err)
		}
		r.scanLogger.Info("discovery", "phase completed")
		if r.repository != nil {
			softDeleted, statusCodes, softErr := r.repository.DeduplicateSoftDeparosRecords(ctx, r.options.ProjectUUID)
			if softErr != nil {
				zap.L().Warn("Deparos soft deduplication failed", zap.Error(softErr))
			} else if softDeleted > 0 {
				detail := fmt.Sprintf("soft-deduplicated %s similar records",
					terminal.Orange(fmt.Sprintf("%d", softDeleted)))
				if len(statusCodes) > 0 {
					detail += " — " + formatStatusCodeMap(statusCodes)
				}
				r.printPhaseFeedback("Discovery", detail)
				r.scanLogger.Info("discovery", fmt.Sprintf("soft-deduplicated %d similar records", softDeleted))
			}
		}
	case PhaseSeed:
		r.setPhaseTag("seed")
		r.scanLogger.Info("seed", "seeding CLI targets")
		if err := r.seedCLITargets(ctx, infra); err != nil {
			r.scanLogger.Error("seed", "CLI target seeding failed: "+err.Error())
			return fmt.Errorf("CLI target seeding failed: %w", err)
		}
		r.scanLogger.Info("seed", "seeding completed")
	case PhaseKnownIssueScan:
		r.setPhaseTag("known-issue-scan")
		r.scanLogger.Info("known-issue-scan", "phase started")
		if err := r.runKnownIssueScanPhase(ctx, infra); err != nil {
			zap.L().Error("KnownIssueScan phase failed", zap.Error(err))
			r.scanLogger.Error("known-issue-scan", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("known-issue-scan", "phase completed")
			r.deduplicateFindings(ctx, "KnownIssueScan")
		}
	case PhaseDynamicAssessment:
		r.setPhaseTag("dynamic-assessment")
		activeModules, passiveModules := r.resolveAllModules(infra)
		if len(activeModules) > 0 || len(passiveModules) > 0 {
			r.scanLogger.InfoWithMeta("dynamic-assessment", "phase started", map[string]interface{}{
				"active_modules":  len(activeModules),
				"passive_modules": len(passiveModules),
			})
			if err := r.runDynamicAssessmentPhase(ctx, infra, activeModules, passiveModules); err != nil {
				zap.L().Error("Dynamic-assessment phase failed", zap.Error(err))
				r.scanLogger.Error("dynamic-assessment", "phase failed: "+err.Error())
			} else {
				r.scanLogger.Info("dynamic-assessment", "phase completed")
			}
		} else {
			zap.L().Info("No modules to execute")
			r.scanLogger.Info("dynamic-assessment", "skipped, no modules to execute")
		}
	}
	return nil
}

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
func (r *Runner) buildInfrastructure() (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-uuid
	scanUUID := r.options.ScanUUID
	if scanUUID == "" {
		scanUUID = uuid.New().String()
		r.options.ScanUUID = scanUUID
	}

	infra := &phaseInfra{
		scanUUID: scanUUID,
	}

	// If SharedInfra is available, reuse its components instead of building fresh
	if r.sharedInfra != nil {
		infra.httpRequester = r.sharedInfra.HTTPRequester
		infra.scopeMatcher = r.sharedInfra.ScopeMatcher
		infra.hostLimiter = r.sharedInfra.HostLimiter
		infra.svc = r.sharedInfra.Services
		infra.jsEngine = r.sharedInfra.JSEngine
		infra.hookChain = r.sharedInfra.HookChain
		// Still need to initialize sessions
		if err := r.initSessions(infra); err != nil {
			if len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0 {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			zap.L().Warn("Failed to initialize sessions", zap.Error(err))
		}
		return infra, nil
	}

	// Create notifier with backends. Each backend is gated by the
	// notify.provider selector — empty means "all", a specific value
	// activates only that channel.
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend
		notifyCfg := &r.settings.Notify

		// Telegram backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderTelegram) {
			tgOpts := r.buildTelegramOptions()
			if tg, err := telegram.NewBackend(tgOpts...); err == nil {
				backends = append(backends, tg)
				zap.L().Info("[Notify] Telegram backend enabled")
			}
		}

		// Discord backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderDiscord) {
			webhookURL := notifyCfg.Discord.WebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
			}
			if webhookURL != "" {
				if dc, err := discord.NewBackend(webhookURL); err == nil {
					backends = append(backends, dc)
					zap.L().Info("[Notify] Discord backend enabled")
				} else {
					zap.L().Warn("[Notify] Failed to create Discord backend", zap.Error(err))
				}
			}
		}

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: notifyCfg.Severities,
			})
		}
	}

	// Create runtime services
	svc := &services.Services{
		Options:      r.options,
		Notifier:     infra.notifier,
		DedupManager: r.dedupManager,
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrors.New(
			r.options.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(r.options.Verbose)
		svc.HostErrors = cache
	}

	// Create HostLimiter for per-host concurrency control
	maxPerHost := r.options.MaxPerHost
	if r.settings != nil && !r.options.MaxPerHostExplicitlySet && r.settings.ScanningPace.MaxPerHost > 0 {
		maxPerHost = r.settings.ScanningPace.MaxPerHost
	}
	if maxPerHost <= 0 {
		maxPerHost = 10
	}
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    maxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc.HostLimiter = hostLimiter
	infra.hostLimiter = hostLimiter
	infra.svc = svc

	httpRequester, err := http.NewRequester(r.options, svc)
	if err != nil {
		infra.Close()
		return nil, errors.Wrap(err, "could not create http requester")
	}
	infra.httpRequester = httpRequester

	// Create scope matcher from settings, passing CLI targets for cli_origin_mode filtering
	if r.settings != nil {
		infra.scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
	}

	// Initialize JS extension engine
	if r.settings != nil && r.settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   r.options.ScanUUID,
			Repository: r.repository,
			LLMClient:  extensionLLMClient(r.settings),
		}
		if r.settings != nil {
			scopeCfg := r.settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
		}
		jsEngine, err := jsext.NewEngine(&r.settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if err != nil {
			zap.L().Warn("Failed to initialize JS extensions", zap.Error(err))
		} else {
			// Create hook chain if hooks are defined
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.hookChain = jsext.NewHookChain(preHooks, postHooks)
				zap.L().Info("JS hooks loaded",
					zap.Int("pre_hooks", len(preHooks)),
					zap.Int("post_hooks", len(postHooks)))
			}
			// Store the engine in infra for module resolution
			infra.jsEngine = jsEngine
		}
	}

	// Initialize multi-session support for IDOR/BOLA testing
	if err := r.initSessions(infra); err != nil {
		// If the user explicitly configured sessions, surface the error clearly
		hasCLIAuth := len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0
		if hasCLIAuth && !r.options.AuthBestEffort {
			return nil, fmt.Errorf("session initialization failed: %w", err)
		}
		zap.L().Warn("Failed to initialize sessions, continuing without session support", zap.Error(err))
	}

	return infra, nil
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
// phaseDeadline derives a phase-scoped context bounded by maxDuration so a phase
// cannot run past its configured scanning_pace max_duration. It is the single
// chokepoint for the "wrap the WHOLE phase, not just one leg" invariant that
// known-issue-scan once regressed on (the Nuclei leg was bounded but the
// Kingfisher leg ran on the raw ctx). When maxDuration <= 0 the phase is
// unbounded: the parent ctx is returned unchanged with a no-op cancel so callers
// can always `defer cancel()`. When the parent already has an earlier deadline
// (e.g. the overall scan budget), context.WithTimeout keeps that earlier
// deadline, so a phase can never extend the scan.
func phaseDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	if maxDuration <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, maxDuration)
}

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
	if len(parts) == 0 {
		return terminal.Gray("all built-in")
	}
	return strings.Join(parts, " ")
}

// runKnownIssueScanPhase orchestrates nuclei + kingfisher batch scanning.
func (r *Runner) runKnownIssueScanPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("KnownIssueScan", "assess security posture with Nuclei templates and third-party validation checks")
	var kisMaxDuration time.Duration
	if r.settings != nil {
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		kisMaxDuration = knownIssueScanPace.MaxDuration
		if knownIssueScanPace.MaxDuration > 0 || knownIssueScanPace.DurationFactor > 0 {
			detail := "Speed:"
			if knownIssueScanPace.MaxDuration > 0 {
				detail += fmt.Sprintf(" max-duration=%s", terminal.HiTeal(knownIssueScanPace.MaxDuration.String()))
			}
			if knownIssueScanPace.DurationFactor > 0 {
				detail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", knownIssueScanPace.DurationFactor)))
			}
			r.printPhaseDetail(detail)
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
	// Kingfisher legs below each derive their OWN max_duration budget from it (see
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
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	if r.repository != nil && r.options.Verbose {
		paths, _ := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
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

	// Track findings by severity
	var mu sync.Mutex
	counts := make(map[severity.Severity]int)

	onResult := func(result *output.ResultEvent) {
		mu.Lock()
		counts[result.Info.Severity]++
		mu.Unlock()

		if err := r.output.Write(result); err != nil {
			zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
		}
	}

	// Nuclei scan on distinct hosts. It gets its OWN max_duration budget so that a
	// long Nuclei run no longer starves the Kingfisher secret scan below — the two
	// legs are bounded independently rather than sharing one budget. A ctx error
	// means this leg's max_duration (or the overall scan) elapsed — that is a
	// curtailment, not a failure.
	nucleiCtx, nucleiCancel := phaseDeadline(ctx, kisMaxDuration)
	defer nucleiCancel()
	if err := r.runKnownIssueScan(nucleiCtx, onResult); err != nil {
		if nucleiCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: Nuclei scan stopped at phase max_duration", zap.Error(nucleiCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: Nuclei scan failed", zap.Error(err))
		}
	}

	// Kingfisher batch scan on all response bodies. It gets a FRESH max_duration
	// budget that starts now (derived from the parent ctx, so still bounded by the
	// overall scan budget), so it always runs even when the Nuclei leg above was
	// curtailed at its deadline. Kingfisher scans DB response bodies locally (no
	// network) and normally finishes well within this budget. Worst-case phase
	// wall-clock is ~2× max_duration, capped by the overall scan budget. A ctx error
	// is a curtailment, distinct from a genuine scanner failure.
	kingfisherCtx, kingfisherCancel := phaseDeadline(ctx, kisMaxDuration)
	defer kingfisherCancel()
	if err := r.runKingfisherBatch(kingfisherCtx, infra, onResult); err != nil {
		if kingfisherCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: Kingfisher secret scan curtailed before all response bodies were scanned — phase max_duration reached", zap.Error(kingfisherCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: Kingfisher batch failed", zap.Error(err))
		}
	}

	// Print summary
	var total int
	for _, c := range counts {
		total += c
	}
	if total > 0 {
		r.printPhaseDetail(formatKnownIssueScanSummary(counts, total))
	}

	// Increment processed_count for KnownIssueScan phase. Use the un-bounded
	// parent ctx so the counter still updates when the phase deadline fired
	// mid-scan (findings were already written; only the budget is exhausted).
	if r.repository != nil && total > 0 {
		if err := r.repository.IncrementProcessedCount(bookkeepingCtx, infra.scanUUID, int64(total)); err != nil {
			zap.L().Warn("KnownIssueScan: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("KnownIssueScan", fmt.Sprintf("completed in %s", terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// runKingfisherBatch scans all response bodies in the database for secrets using Kingfisher.
func (r *Runner) runKingfisherBatch(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent)) error {
	if r.repository == nil {
		return fmt.Errorf("kingfisher batch: database repository required")
	}

	scanner, err := kingfisher.NewScanner(nil)
	if err != nil {
		return fmt.Errorf("kingfisher batch: failed to create scanner: %w", err)
	}
	if err := scanner.EnsureBinary(ctx); err != nil {
		return fmt.Errorf("kingfisher batch: binary unavailable: %w", err)
	}

	zap.L().Info("KnownIssueScan: Kingfisher batch — scanning response bodies for secrets")

	var cursor string
	var totalFindings int
	for {
		// Break promptly when the phase/scan budget elapses. A single batch holds up
		// to kingfisherBatchSize records, so without an inner-loop check below the
		// per-record loop would scan every body before the next-batch fetch could
		// observe cancellation. Returning ctx.Err() lets the caller log the
		// secret-scan curtailment notice rather than treating it as a failure.
		if err := ctx.Err(); err != nil {
			return err
		}

		records, err := r.repository.GetRecordsWithResponseBody(ctx, r.options.ProjectUUID, cursor, kingfisherBatchSize)
		if err != nil {
			return fmt.Errorf("kingfisher batch: failed to fetch records: %w", err)
		}
		if len(records) == 0 {
			break
		}

		for _, record := range records {
			cursor = record.UUID

			if err := ctx.Err(); err != nil {
				return err
			}

			// Filter by content type (reuse IsTextBasedMIME from secret_detect)
			if !secret_detect.IsTextBasedMIME(record.ResponseContentType) {
				continue
			}

			result, scanErr := scanner.Scan(ctx, record.ResponseBodyBytes())
			if scanErr != nil || !result.HasFindings() {
				continue
			}

			for i := range result.Findings {
				f := &result.Findings[i]

				sev := severity.High
				conf := severity.Firm
				if f.IsValidated() {
					sev = severity.Critical
					conf = severity.Certain
				}

				event := &output.ResultEvent{
					ModuleID: "",
					Info: output.Info{
						Name:        f.RuleName(),
						Description: "Leaked secret detected: " + f.RuleID(),
						Severity:    sev,
						Confidence:  conf,
						Tags:        []string{"secret", "credential", "exposure", "known-issue-scan"},
					},
					Host:             record.Hostname,
					URL:              record.URL,
					Matched:          record.URL,
					ExtractedResults: []string{f.Snippet()},
					Metadata: map[string]any{
						"rule_id":   f.RuleID(),
						"rule_name": f.RuleName(),
						"validated": f.IsValidated(),
					},
					ModuleType:    database.ModuleTypeSecretScan,
					FindingSource: database.FindingSourceKnownIssueScan,
					ModuleShort:   "Leaked secret detected in HTTP response body",
				}

				// Save to DB
				if saveErr := r.repository.SaveFinding(ctx, event, []string{record.UUID}, infra.scanUUID, r.options.ProjectUUID); saveErr != nil {
					zap.L().Debug("Failed to save kingfisher finding", zap.Error(saveErr))
				}

				// Write to output via callback
				if onResult != nil {
					onResult(event)
				}
				totalFindings++
			}
		}

		if len(records) < kingfisherBatchSize {
			break
		}
	}

	zap.L().Info("KnownIssueScan: Kingfisher batch completed", zap.Int("findings", totalFindings))
	return nil
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
	if infra.jsEngine != nil {
		jsActive := len(infra.jsEngine.ActiveModules())
		jsPassive := len(infra.jsEngine.PassiveModules())
		if jsActive+jsPassive > 0 {
			modulesLine += fmt.Sprintf(" (incl. %s extensions)",
				terminal.HiTeal(fmt.Sprintf("%d", jsActive+jsPassive)))
		}
	}
	r.printPhaseDetail(modulesLine)

	daSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		if daPace.MaxDuration > 0 {
			daSpeedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(daPace.MaxDuration.String()))
		}
		if daPace.DurationFactor > 0 {
			daSpeedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", daPace.DurationFactor)))
		}
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
			terminal.TipPrefix(), terminal.Gray("increase feedback rounds to re-scan newly discovered URLs via"), terminal.HiCyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
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

	// If KnownIssueScan was enabled, filter out secret-detect to avoid duplicate kingfisher findings
	if r.options.KnownIssueScanEnabled {
		passiveModules = filterOutPassiveModule(passiveModules, secret_detect.ModuleID)
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
	daConcurrency := r.options.Concurrency
	if r.settings != nil && !r.options.ConcurrencyExplicitlySet {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		if daPace.Concurrency > 0 {
			daConcurrency = daPace.Concurrency
		}
	}

	// Initialize OAST service if enabled
	var oastService *oast.Service
	if r.settings != nil && r.settings.OAST.Enabled {
		onOASTResult := func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write OAST result", zap.Error(err))
			}
		}
		var err error
		oastService, err = oast.New(&r.settings.OAST, onOASTResult, r.repository, infra.scanUUID, r.options.ProjectUUID, nil)
		if err != nil {
			zap.L().Warn("DynamicAssessment: OAST initialization failed, continuing without OAST", zap.Error(err))
		}
		if oastService != nil {
			oastService.Start()
			defer oastService.Close()
			r.printPhaseDetail(fmt.Sprintf("OAST: enabled via %s (out-of-band callback detection active)", oastService.ServerURL()))
		}
	}

	// Compute in-scope hostnames to filter DB records by CLI target hostnames
	inScopeHostnames := r.getInScopeDBHostnamesList(ctx)

	// Shared insertion point cache across feedback rounds to avoid cold-start overhead
	ipCache, _ := lru.New[string, []httpmsg.InsertionPoint](4096)

	// Resolve per-phase settings from scanning pace config (static across rounds)
	var daMaxDuration time.Duration
	daParallelPassive := true // default for dynamic-assessment phase
	var daFeedbackDrain time.Duration
	var daActiveModuleTimeout time.Duration
	if r.settings != nil {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		daMaxDuration = daPace.MaxDuration
		daParallelPassive = daPace.ParallelPassive
		daFeedbackDrain = daPace.FeedbackDrainTimeout
		daActiveModuleTimeout = daPace.ActiveModuleTimeout
	}

	// Enforce dynamic-assessment phase deadline across all feedback rounds. Without this wrap
	// each round's executor would start a fresh timeout, letting total phase time
	// reach feedbackRounds × daMaxDuration.
	var phaseCancel context.CancelFunc
	ctx, phaseCancel = phaseDeadline(ctx, daMaxDuration)
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
	if r.repository != nil {
		recordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		defer recordWriter.Close()
	}

	// phaseModuleTimeouts is shared across every per-round executor so the
	// timed-out total in the status line accumulates over the whole phase rather
	// than resetting each feedback round (Records/Findings are per-round by design).
	var phaseModuleTimeouts atomic.Int64

	baseExecutorCfg := core.ExecutorConfig{
		Workers:              daConcurrency,
		Services:             infra.svc,
		HTTPRequester:        infra.httpRequester,
		Repository:           r.repository,
		RecordWriter:         recordWriter,
		ScanUUID:             infra.scanUUID,
		ScopeMatcher:         infra.scopeMatcher,
		ModuleTimeouts:       &phaseModuleTimeouts,
		SkipBaseline:         true,
		PauseCtrl:            r.pauseCtrl,
		MaxFindingsPerModule: r.options.MaxFindingsPerModule,
		TechFilterDisabled:   r.options.NoTechFilter || strings.EqualFold(r.options.Intensity, "deep"),
		OnTechDetected: func(host, tag string) {
			line := fmt.Sprintf("%s %s %s %s %s %s\n",
				terminal.Muted(terminal.SymbolChevron+" tech-stack "+terminal.SymbolPipe),
				terminal.BoldCyan("[detected]"),
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
		// emitResult (executor.go:1474-1488 — one row per finding with an
		// attached request/response pair) would get polled back into the
		// scan and fan out 1 ingested request → hundreds of re-scanned rows.
		sorSourceFilter := database.IngestRecordSources

		continuousSource := database.NewDBInputSource(r.repository.DB(), r.repository, infra.scanUUID, 2*time.Second).
			WithHostnames(inScopeHostnames).
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
					if cnt, cErr := r.repository.CountRecordsAfterCursorBySource(ctx, s.StartedAt, "", sorSourceFilter, inScopeHostnames); cErr == nil {
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
		if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
			logModuleMetrics(metrics)
		}
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}

	// Feedback loop: re-scan newly discovered URLs
	for round := 0; round < feedbackRounds; round++ {
		processed, err := r.runDynamicAssessmentRound(ctx, infra, round, inScopeHostnames, activeModules, passiveModules, baseExecutorCfg, oastService)
		if err != nil {
			zap.L().Error("DynamicAssessment: executor error", zap.Error(err), zap.Int("round", round))
			break
		}

		// Deduplicate findings after each dynamic-assessment round
		r.deduplicateFindings(ctx, "DynamicAssessment")

		if ctx.Err() != nil {
			zap.L().Info("DynamicAssessment: phase deadline reached, stopping feedback loop",
				zap.Int("round", round+1), zap.Error(ctx.Err()))
			break
		}

		if round < feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHostnames)
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
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHostnames)
			if countErr == nil && newCount > 0 {
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Orange(fmt.Sprintf("%d", newCount)), terminal.Gray(fmt.Sprintf("new records discovered but skipped (max_feedback_rounds=%d)", feedbackRounds)))
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Gray("enable multi-round scanning via"), terminal.Cyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
			}
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("DynamicAssessment", fmt.Sprintf("all rounds completed in %s", terminal.HiPurple(fmtDuration(elapsed))))

	return nil
}

func (r *Runner) runDynamicAssessmentRound(
	ctx context.Context,
	infra *phaseInfra,
	round int,
	inScopeHostnames []string,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
	baseCfg core.ExecutorConfig,
	oastService *oast.Service,
) (int64, error) {
	roundStart := time.Now()
	dbSource := database.NewRiskPrioritizedDBInputSource(r.repository.DB(), r.repository, infra.scanUUID).
		WithHostnames(inScopeHostnames)

	executor := core.NewExecutor(baseCfg, dbSource, activeModules, passiveModules)
	if oastService != nil {
		oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
	}
	_, err := executor.Execute(ctx)

	if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
		logModuleMetrics(metrics)
	}
	if c := infra.httpRequester.Clusterer(); c != nil {
		c.LogStats()
	}
	if err != nil {
		return 0, err
	}

	processed := executor.Processed()
	roundElapsed := time.Since(roundStart)
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
	return processed, nil
}

func (r *Runner) countRemainingDynamicAssessmentRecords(ctx context.Context, scanUUID string, hostnames []string) (int64, error) {
	currentScan, err := r.repository.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		return 0, err
	}
	return r.repository.CountRecordsAfterCursor(ctx, currentScan.CursorAt, currentScan.CursorUUID, hostnames...)
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

// runKnownIssueScan executes known issue scanning using the nuclei Go library.
func (r *Runner) runKnownIssueScan(ctx context.Context, onResult func(*output.ResultEvent)) error {
	if r.repository == nil {
		return fmt.Errorf("known-issue-scan: database repository required")
	}

	// Query distinct paths from DB and build targets
	paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
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

	zap.L().Info("KnownIssueScan: targets from database", zap.Int("count", len(targets)))

	// Build KnownIssueScan config from settings
	cfg := knownissuescan.Config{
		Targets:     targets,
		Concurrency: r.options.Concurrency,
		ScanUUID:    r.options.ScanUUID,
		ProjectUUID: r.options.ProjectUUID,
		ProxyURL:    r.options.ProxyURL,
		Headers:     r.options.Headers,
		OnResult:    onResult,
		Repository:  r.repository,
	}

	// Apply YAML settings
	if r.settings != nil {
		knownIssueScanCfg := &r.settings.KnownIssueScan
		cfg.Tags = knownIssueScanCfg.Tags
		cfg.ExcludeTags = knownIssueScanCfg.ExcludeTags
		cfg.Severities = knownIssueScanCfg.Severities
		if knownIssueScanCfg.TemplatesDir != "" {
			cfg.TemplatesDir = config.ExpandPath(knownIssueScanCfg.TemplatesDir)
		}

		// scanning_pace.known-issue-scan controls speed
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		if !r.options.ConcurrencyExplicitlySet && knownIssueScanPace.Concurrency > 0 {
			cfg.Concurrency = knownIssueScanPace.Concurrency
		}
		if knownIssueScanPace.RateLimit > 0 {
			cfg.RateLimit = knownIssueScanPace.RateLimit
		}
		if knownIssueScanPace.MaxDuration > 0 {
			cfg.Timeout = knownIssueScanPace.MaxDuration
		}
	}

	return knownissuescan.Run(ctx, cfg)
}

// runExternalHarvestPhase runs external intelligence harvesting as a standalone phase.
// Harvested URLs are ingested into the httpRecords table via an Executor with zero modules.
func (r *Runner) runExternalHarvestPhase(ctx context.Context, infra *phaseInfra) error {
	if len(r.options.Targets) == 0 {
		return nil
	}

	phaseStart := time.Now()

	src := r.buildExternalHarvesterSource()
	if src == nil {
		zap.L().Warn("ExternalHarvest: no source could be built, skipping")
		return nil
	}

	r.printPhaseStart("ExternalHarvest", "harvest URLs from external intelligence sources")

	ehSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		ehPace := r.settings.ScanningPace.ResolvePhase("external_harvester")
		if ehPace.MaxDuration > 0 {
			ehSpeedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(ehPace.MaxDuration.String()))
		}
		if ehPace.DurationFactor > 0 {
			ehSpeedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", ehPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(ehSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	zap.L().Info("ExternalHarvest: ingesting harvested URLs into database")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("harvest"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, src, nil, nil)
	_, err := executor.Execute(ctx)
	if err != nil {
		return err
	}

	// Increment processed_count for external harvest phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("ExternalHarvest: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("ExternalHarvest", fmt.Sprintf("completed — %s items ingested in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())), terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("ExternalHarvest: completed", zap.Int64("processed", executor.Processed()))
	return nil
}
