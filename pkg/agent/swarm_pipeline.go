package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/authsession"
	"github.com/vigolium/vigolium/pkg/agent/extensions"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

type swarmPhaseStep interface {
	Run(context.Context, *swarmPipelineState) error
}

type swarmPipelineState struct {
	runner *SwarmRunner
	cfg    SwarmConfig

	agenticScan *database.AgenticScan
	result      *SwarmResult

	sessionDir       string
	checkpoint       *SwarmCheckpoint
	completedPhases  []string
	phaseTimings     map[string]time.Duration
	recordStats      swarmRecordStats
	targetURL        string
	records          []*httpmsg.HttpRequestResponse
	plan             *SwarmPlan
	sourceExtensions []GeneratedExtension
	extensionDir     string
	extensionRenames map[string]string
	batchProv        *BatchProvenance
	stop             bool

	// techStack is the reconnaissance sweep result for the target host,
	// populated by reconSwarmStep when running in black-box mode (no --source).
	// nil when source-analysis ran, when the user passed --skip recon, or when
	// the sweep produced no actionable signal. When non-nil, its markdown
	// rendering is threaded into the plan agent's prompt context.
	techStack *recon.TechStackReport
}

func (s *SwarmRunner) runSwarmPipeline(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, result *SwarmResult) error {
	state, cleanup, err := s.newSwarmPipelineState(ctx, cfg, agenticScan, result)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	steps := []swarmPhaseStep{
		normalizeSwarmStep{},
		authSwarmStep{},
		sourceAnalysisSwarmStep{},
		discoverySwarmStep{},
		reconSwarmStep{},
		planSwarmStep{},
		discoverReentrySwarmStep{},
		extensionSwarmStep{},
		scanSwarmStep{},
		replanOnEmptySwarmStep{},
		triageSwarmStep{},
		finalizeSwarmStep{},
	}

	for _, step := range steps {
		if state.stop {
			break
		}
		if err := step.Run(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func (s *SwarmRunner) newSwarmPipelineState(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, result *SwarmResult) (*swarmPipelineState, func(), error) {
	sessionDir := cfg.SessionDir
	if cfg.ResumeDir != "" {
		sessionDir = cfg.ResumeDir
	}
	if sessionDir == "" {
		var err error
		sessionDir, err = EnsureSessionDir(cfg.SessionsDir, agenticScan.UUID)
		if err != nil {
			zap.L().Warn("Failed to create session dir, falling back to temp dirs", zap.Error(err))
		}
	}
	result.SessionDir = sessionDir
	cfg.SessionDir = sessionDir

	browserEnabled := s.engine != nil && s.engine.settings != nil && s.engine.settings.Agent.Browser.IsEnabled()
	CopySkillsToSessionDir(sessionDir, browserEnabled)

	var cleanup func()
	// Pass swarm's own AgenticScan UUID as the audit child's parentAgenticScanUUID.
	// This marks audit as a nested run (so NewAuditAgenticScanner knows to
	// generate a fresh UUID instead of colliding with the swarm parent's
	// filepath.Base(SessionDir)), and wires the parent/child relationship
	// for `vigolium agent session` display.
	if _, wait, _ := startAuditAgentBackground(ctx, cfg.Audit, cfg.AuditHarness, cfg.SourcePath, sessionDir, cfg.ProjectUUID, cfg.ScanUUID, agenticScan.UUID, s.repo, cfg.StreamWriter, func(msg string) {
		fmt.Fprintf(os.Stderr, "%s audit: %s\n", terminal.InfoSymbol(), msg)
	}); wait != nil {
		cleanup = wait
	}

	var checkpoint *SwarmCheckpoint
	if cfg.ResumeDir != "" {
		cp, err := loadCheckpoint(cfg.ResumeDir)
		if err != nil {
			zap.L().Warn("Failed to load checkpoint, starting fresh", zap.Error(err))
		} else {
			checkpoint = cp
			zap.L().Info("Resuming from checkpoint",
				zap.String("last_phase", cp.LastPhase()),
				zap.Strings("completed", cp.CompletedPhases))
		}
	}

	return &swarmPipelineState{
		runner:       s,
		cfg:          cfg,
		agenticScan:  agenticScan,
		result:       result,
		sessionDir:   sessionDir,
		checkpoint:   checkpoint,
		phaseTimings: make(map[string]time.Duration),
	}, cleanup, nil
}

func (ps *swarmPipelineState) startPhase(ctx context.Context, phase string, emit bool) time.Time {
	ps.agenticScan.CurrentPhase = phase
	ps.runner.persistPhase(ctx, ps.agenticScan)
	if emit {
		ps.runner.emitPhase(ps.cfg, phase)
	}
	return time.Now()
}

func (ps *swarmPipelineState) finishPhase(phase string, started time.Time) {
	ps.phaseTimings[phase] = time.Since(started)
	ps.completedPhases = append(ps.completedPhases, phase)
}

func (ps *swarmPipelineState) writeCheckpoint(plan *SwarmPlan, triageRound int) {
	if err := ps.runner.writeSwarmCheckpoint(
		ps.sessionDir,
		ps.cfg.ProjectUUID,
		ps.completedPhases,
		ps.targetURL,
		len(ps.records),
		plan,
		ps.extensionDir,
		triageRound,
		ps.extensionRenames,
		ps.result,
		ps.recordStats,
	); err != nil {
		zap.L().Warn("Failed to write swarm checkpoint", zap.Error(err))
	}
}

type normalizeSwarmStep struct{}

func (normalizeSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	started := ps.startPhase(ctx, SwarmPhaseNormalize, false)

	records, targetURL, err := ps.runner.normalizeInputs(ctx, ps.cfg)
	if err != nil {
		return fmt.Errorf("input normalization failed: %w", err)
	}
	ps.records = records
	ps.targetURL = targetURL
	if targetURL != "" {
		ps.agenticScan.TargetURL = targetURL
	}
	ps.agenticScan.InputType = string(ps.cfg.InputType)
	if ps.agenticScan.InputType == "" && len(ps.cfg.Inputs) > 0 {
		ps.agenticScan.InputType = string(agentinput.DetectInputType(ps.cfg.Inputs[0]))
	}

	recordUUIDs := ps.runner.validateProbeAndSave(ctx, ps.records, nil, nil, "agent-swarm", ps.cfg.ProjectUUID, ps.cfg.probeConfig())
	ps.agenticScan.RecordCount = len(recordUUIDs)
	ps.result.TotalRecords = len(recordUUIDs)
	ps.recordStats.Initial = len(ps.records)

	writeInputsToSessionDir(ps.sessionDir, ps.records, ps.cfg.SourcePath)
	ps.finishPhase(SwarmPhaseNormalize, started)
	zap.L().Info("Agent swarm phase completed", zap.String("phase", SwarmPhaseNormalize), zap.Int("records", len(ps.records)))
	fmt.Fprintf(os.Stderr, "%s Phase [%s] %s input records\n",
		terminal.InfoSymbol(),
		terminal.BoldOrange(SwarmPhaseNormalize),
		terminal.Orange(fmt.Sprintf("%d", len(ps.records))))
	return nil
}

type authSwarmStep struct{}

func (authSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	// --browser-auth requires --browser; otherwise the user passed --browser-auth but we have
	// no way to drive a login flow. Surface that loudly so they don't wonder
	// where their auth went.
	if ps.cfg.Auth && !ps.cfg.Browser {
		ps.runner.addWarning(ps.result, "ignoring --browser-auth: --browser was not enabled (auth phase needs the browser agent to drive login)")
		fmt.Fprintf(os.Stderr, "%s --browser-auth was set but --browser is off; skipping the browser-based auth phase. Pass --browser to enable it.\n", terminal.WarningSymbol())
	}
	if !ps.cfg.Auth || !ps.cfg.Browser || phaseCompleted(ps.checkpoint, SwarmPhaseAuth) {
		return nil
	}
	started := ps.startPhase(ctx, SwarmPhaseAuth, true)
	authConfigPath, err := ps.runner.runAuthPhase(ctx, ps.cfg, ps.targetURL, ps.sessionDir)
	if err != nil {
		zap.L().Warn("Auth phase failed, continuing without browser auth", zap.Error(err))
		ps.runner.addWarning(ps.result, "auth phase failed: %v", err)
		printPhaseLine(SwarmPhaseAuth, fmt.Sprintf("failed: %v", err))
	} else if authConfigPath != "" {
		printPhaseLine(SwarmPhaseAuth, fmt.Sprintf("auth config saved: %s", terminal.ShortenHome(authConfigPath)))
		// Thread the captured session into the discovery / scan funcs so
		// the native spider crawls post-login surface. Without this the
		// browser auth output sat unused after this phase.
		if ps.cfg.BrowserAuthCallback != nil {
			if cbErr := ps.cfg.BrowserAuthCallback(authConfigPath); cbErr != nil {
				zap.L().Warn("BrowserAuthCallback failed", zap.Error(cbErr))
				ps.runner.addWarning(ps.result, "browser-auth callback failed: %v", cbErr)
			}
		}
	}
	ps.finishPhase(SwarmPhaseAuth, started)
	return nil
}

type sourceAnalysisSwarmStep struct{}

func (sourceAnalysisSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.cfg.SourcePath == "" || phaseCompleted(ps.checkpoint, SwarmPhaseSourceAnalysis) {
		if ps.cfg.SourceAnalysisOnly || (ps.targetURL == "" && ps.cfg.SourcePath != "") {
			ps.result.TotalRecords = len(ps.records)
			ps.result.PhaseTimings = ps.phaseTimings
			ps.stop = true
		}
		return nil
	}

	started := ps.startPhase(ctx, SwarmPhaseSourceAnalysis, true)
	var saRecords []*httpmsg.HttpRequestResponse
	var saNotes []string
	var saExtensions []GeneratedExtension
	var discoveredSessionConfig *AgentSessionConfig

	saCfg := SourceAnalysisConfig{
		AgentName:      ps.cfg.AgentName,
		TargetURL:      ps.targetURL,
		SourcePath:     ps.cfg.SourcePath,
		Files:          ps.cfg.Files,
		Instruction:    ps.cfg.Instruction,
		DryRun:         ps.cfg.DryRun,
		ShowPrompt:     ps.cfg.ShowPrompt,
		ScanUUID:       ps.cfg.ScanUUID,
		ProjectUUID:    ps.cfg.ProjectUUID,
		StreamWriter:   ps.cfg.StreamWriter,
		SessionDir:     ps.sessionDir,
		MaxConcurrency: ps.cfg.SAMaxConcurrency,
	}

	// No outer retry wrapper here: each of the 4 source-analysis sub-calls
	// already retries via Engine.Run → retryAgentCall, so wrapping the whole
	// wave would re-run every successful sub-call on a single transient
	// failure (4× cost). Sub-call errors propagate as partial-success warnings.
	saResult, saRawOutput, saRenderedPrompt, saErr := ps.runner.engine.RunSourceAnalysisParallel(ctx, saCfg)

	writePromptToSessionDir(ps.sessionDir, "source-analysis-prompt.md", saRenderedPrompt)
	if ps.sessionDir != "" && saRawOutput != "" {
		outputPath := filepath.Join(ps.sessionDir, "source-analysis-output.md")
		writeSessionArtifact(outputPath, []byte(saRawOutput))
		printPhaseLine("source-analysis", fmt.Sprintf("%s output: %s", terminal.SymbolStart, terminal.ShortenHome(outputPath)))
	}

	if saErr != nil {
		zap.L().Warn("Source analysis failed, continuing with input records only", zap.Error(saErr))
		ps.runner.addWarning(ps.result, "source analysis failed: %v", saErr)
	} else if saResult != nil {
		printPhaseLine("source-analysis", fmt.Sprintf("result: %d http_records, %d extensions  has_session_config=%v",
			len(saResult.HTTPRecords), len(saResult.Extensions), saResult.SessionConfig != nil))

		filteredRecords, filteredNotes := filterSourceRecordsByHostname(saResult.HTTPRecords, ps.targetURL)
		if len(filteredRecords) > 0 {
			printPhaseLine("source-analysis", fmt.Sprintf("appending source-discovered routes  total=%d hostname_matched=%d",
				len(saResult.HTTPRecords), len(filteredRecords)))
			saRecords = filteredRecords
			saNotes = filteredNotes
		}
		saExtensions = append(saExtensions, saResult.Extensions...)
		ps.cfg.CredentialSets = resolveIntentCredentialSets(ps.cfg.Credentials, ps.cfg.CredentialSets)
		if len(ps.cfg.CredentialSets) > 0 && saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
			saResult.SessionConfig = applyIntentCredentialsToSessionConfig(saResult.SessionConfig, ps.cfg.CredentialSets)
			printPhaseLine("source-analysis", fmt.Sprintf("applied %d prompt credential set(s) to discovered login flows", len(ps.cfg.CredentialSets)))
		}
		if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
			vr := authsession.ValidateSessionConfigDetailed(saResult.SessionConfig)
			if len(vr.Invalid) > 0 {
				printPhaseLine("source-analysis", fmt.Sprintf("session config: %d valid, %d invalid — attempting LLM repair", len(vr.Valid), len(vr.Invalid)))
				invalidCfg := &AgentSessionConfig{}
				for _, inv := range vr.Invalid {
					invalidCfg.Sessions = append(invalidCfg.Sessions, inv.Entry)
				}
				repaired := RepairInvalidSessionConfig(ctx, ps.runner.engine, invalidCfg, ps.targetURL, RepairConfig{
					AgentName:    ps.cfg.AgentName,
					ShowPrompt:   ps.cfg.ShowPrompt,
					ExploreNotes: saResult.SessionExploreNotes,
				})
				if repaired != nil {
					printPhaseLine("source-analysis", fmt.Sprintf("LLM repaired %d session entries", len(repaired.Sessions)))
					vr.Valid = append(vr.Valid, repaired.Sessions...)
				} else if len(vr.Valid) == 0 {
					printPhaseLine("source-analysis", "LLM session config repair failed, continuing without auth")
				}
			}
			if len(vr.Valid) > 0 {
				saResult.SessionConfig = &AgentSessionConfig{Sessions: vr.Valid}
			} else {
				saResult.SessionConfig = nil
			}
		}
		if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
			writeSessionConfigToDir(saResult.SessionConfig, ps.sessionDir)
			discoveredSessionConfig = saResult.SessionConfig
			loginRecords := authsession.SessionConfigToHTTPRecords(saResult.SessionConfig)
			if len(loginRecords) > 0 {
				loginFiltered, loginNotes := filterSourceRecordsByHostname(loginRecords, ps.targetURL)
				if len(loginFiltered) > 0 {
					printPhaseLine("source-analysis", fmt.Sprintf("appending login endpoint records  count=%d", len(loginFiltered)))
					saRecords = append(saRecords, loginFiltered...)
					saNotes = append(saNotes, loginNotes...)
				}
			}
		}
		if ps.cfg.SourceAnalysisCallback != nil {
			if err := ps.cfg.SourceAnalysisCallback(saResult); err != nil {
				zap.L().Warn("Source analysis callback failed", zap.Error(err))
				ps.runner.addWarning(ps.result, "source analysis callback failed: %v", err)
			}
		}
	}

	authHeaders := ps.hydrateSourceAnalysisSessions(ctx, discoveredSessionConfig, saRecords)
	ps.runner.validateProbeAndSave(ctx, saRecords, saNotes, authHeaders, "agent-swarm-source", ps.cfg.ProjectUUID, ps.cfg.probeConfig())
	if len(saRecords) > 0 {
		printPhaseLine("source-analysis", fmt.Sprintf("%s source analysis routes: %d %s", terminal.SymbolBullet, len(saRecords), formatRouteStatusSummary(saRecords)))
	}

	if ps.cfg.CodeAudit && !phaseCompleted(ps.checkpoint, SwarmPhaseCodeAudit) {
		codeAuditStarted := ps.startPhase(ctx, SwarmPhaseCodeAudit, true)
		reuseExploreSession := saRawOutput != ""
		findingsSaved, err := ps.runner.runCodeAudit(ctx, ps.cfg, ps.targetURL, ps.sessionDir, saRawOutput, reuseExploreSession)
		if err != nil {
			zap.L().Warn("Code audit failed, continuing", zap.Error(err))
			ps.runner.addWarning(ps.result, "code audit failed: %v", err)
		} else if findingsSaved > 0 {
			printPhaseLine("code-audit", fmt.Sprintf("%s %d findings saved to database", terminal.SymbolBullet, findingsSaved))
		} else {
			printPhaseLine("code-audit", "no findings")
		}
		ps.finishPhase(SwarmPhaseCodeAudit, codeAuditStarted)
	}

	ps.records = append(ps.records, saRecords...)
	ps.result.TotalRecords = len(ps.records)
	ps.recordStats.Source = len(saRecords)
	ps.sourceExtensions = append(ps.sourceExtensions, saExtensions...)

	if ps.runner.repo != nil && ps.targetURL != "" {
		hostname := hostnameFromURL(ps.targetURL)
		if hostname != "" {
			ps.runner.reprobeUnprobedRecords(ctx, ps.cfg.ProjectUUID, hostname, authHeaders, "agent-swarm-source")
		}
	}
	if len(saRecords) > 0 {
		printPhaseLine("source-analysis", fmt.Sprintf("%s routes discovered: %d %s",
			terminal.SymbolBullet, len(saRecords), formatRouteStatusSummary(saRecords)))
	}
	if ps.sessionDir != "" && len(ps.sourceExtensions) > 0 {
		writeSourceExtensionsToSessionDir(ps.sourceExtensions, ps.sessionDir)
	}

	ps.finishPhase(SwarmPhaseSourceAnalysis, started)
	printPhaseLine("source-analysis", fmt.Sprintf("%s completed — %d routes, %d extensions in %s",
		terminal.SymbolSuccess, len(saRecords), len(ps.sourceExtensions), ps.phaseTimings[SwarmPhaseSourceAnalysis].Round(time.Second)))
	ps.writeCheckpoint(nil, 0)

	if ps.cfg.SourceAnalysisOnly {
		ps.result.TotalRecords = len(ps.records)
		ps.result.PhaseTimings = ps.phaseTimings
		ps.stop = true
	} else if ps.targetURL == "" && ps.cfg.SourcePath != "" {
		fmt.Fprintf(os.Stderr, "%s Source-only analysis complete. Skipping dynamic phases (no --target).\n", terminal.InfoSymbol())
		ps.result.TotalRecords = len(ps.records)
		ps.result.PhaseTimings = ps.phaseTimings
		ps.stop = true
	}
	return nil
}

func (ps *swarmPipelineState) hydrateSourceAnalysisSessions(ctx context.Context, discoveredSessionConfig *AgentSessionConfig, saRecords []*httpmsg.HttpRequestResponse) map[string]string {
	var authHeaders map[string]string
	if discoveredSessionConfig != nil {
		authHeaders = hydrateSessionConfig(discoveredSessionConfig)
		if len(authHeaders) > 0 {
			printPhaseLine("source-analysis", fmt.Sprintf("hydrated auth headers  count=%d", len(authHeaders)))
		}
		if ps.runner.repo != nil && ps.targetURL != "" {
			hostname := hostnameFromURL(ps.targetURL)
			if hostname != "" {
				rows := authsession.AgentSessionConfigToAuthenticationHostnames(discoveredSessionConfig, ps.cfg.ProjectUUID, ps.cfg.ScanUUID, hostname, "agent-swarm-source")
				if len(authHeaders) > 0 {
					now := time.Now()
					for _, r := range rows {
						r.HydratedAt = &now
					}
				}
				if len(rows) > 0 {
					if err := ps.runner.repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
						zap.L().Warn("Failed to persist session config to database", zap.Error(err))
					} else {
						printPhaseLine("source-analysis", fmt.Sprintf("persisted session config  hostname=%s sessions=%d", hostname, len(rows)))
					}
				}
			}
		}
	}
	if len(authHeaders) == 0 && ps.runner.repo != nil && ps.targetURL != "" {
		hostname := hostnameFromURL(ps.targetURL)
		if hostname != "" {
			dbRows, err := ps.runner.repo.GetAuthenticationHostnamesByHostname(ctx, ps.cfg.ProjectUUID, hostname)
			if err == nil && len(dbRows) > 0 {
				authHeaders = authsession.AuthHeadersFromAuthenticationHostnames(dbRows)
				if len(authHeaders) > 0 {
					printPhaseLine("source-analysis", fmt.Sprintf("loaded auth headers from DB  hostname=%s count=%d", hostname, len(authHeaders)))
				}
			}
		}
	}
	if discoveredSessionConfig != nil && len(discoveredSessionConfig.Sessions) > 0 {
		if len(authHeaders) > 0 {
			printPhaseLine("source-analysis", fmt.Sprintf("%s sessions: %d discovered, %d auth tokens obtained", terminal.SymbolBullet, len(discoveredSessionConfig.Sessions), len(authHeaders)))
		} else {
			printPhaseLine("source-analysis", fmt.Sprintf("%s sessions: %d discovered, no auth tokens obtained", terminal.SymbolBullet, len(discoveredSessionConfig.Sessions)))
		}
	}
	if len(authHeaders) > 0 && len(saRecords) > 0 {
		authsession.ReplaceAuthHeadersInHTTPRR(saRecords, authHeaders)
	}
	return authHeaders
}

type discoverySwarmStep struct{}

func (discoverySwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop || ps.cfg.DiscoverFunc == nil || phaseCompleted(ps.checkpoint, SwarmPhaseDiscover) {
		return nil
	}
	started := ps.startPhase(ctx, SwarmPhaseDiscover, true)
	if err := ps.cfg.DiscoverFunc(ctx); err != nil {
		zap.L().Warn("Discovery phase failed, continuing with input records", zap.Error(err))
		ps.runner.addWarning(ps.result, "discovery phase failed: %v", err)
	} else if ps.runner.repo != nil {
		discoveredRecords := ps.runner.queryDiscoveredRecords(ctx, ps.cfg, ps.targetURL)
		if len(discoveredRecords) > 0 {
			zap.L().Info("Merging discovered records from discovery phase", zap.Int("discovered", len(discoveredRecords)), zap.Int("existing", len(ps.records)))
			ps.records = deduplicateRecords(append(ps.records, discoveredRecords...))
			ps.recordStats.Discovery = len(discoveredRecords)
			ps.result.TotalRecords = len(ps.records)
		}
	}
	ps.finishPhase(SwarmPhaseDiscover, started)
	fmt.Fprintf(os.Stderr, "  %s Total records after discovery: %s\n", terminal.Cyan(terminal.SymbolBullet), terminal.Orange(fmt.Sprintf("%d", len(ps.records))))
	return nil
}

type reconSwarmStep struct{}

// Run executes the lightweight tech-stack reconnaissance sweep against the
// target host before the plan agent runs. The phase is intentionally cheap
// (~5s, GET-only on a curated path set) and conservative (no payloads, no
// method fuzzing) — its job is to enrich the planner's prompt with stack
// hints, exposed API specs, CORS posture, and security-header gaps that
// black-box scans would otherwise have to infer from raw records.
//
// Skip conditions, in order:
//   - the user passed --skip recon
//   - --source was provided (source-analysis already produced stack hints)
//   - the checkpoint marks this phase complete
//   - no target URL is available (record-UUID-only runs)
//
// Failures are non-fatal: a sweep error is logged and recorded as a
// warning, but the pipeline proceeds with no tech-stack context.
func (reconSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop {
		return nil
	}
	if PhaseSkipped(ps.cfg.SkipPhases, SwarmPhaseRecon) {
		zap.L().Info("Skipping recon phase (--skip recon)")
		return nil
	}
	if ps.cfg.SourcePath != "" {
		// Source-analysis already inferred the stack; an extra recon sweep
		// would just double-spend the prompt budget. Logged at debug so
		// users running with --source aren't surprised by missing recon
		// console output.
		zap.L().Debug("Skipping recon phase (source path provided)")
		return nil
	}
	if phaseCompleted(ps.checkpoint, SwarmPhaseRecon) {
		return nil
	}
	if ps.targetURL == "" {
		zap.L().Debug("Skipping recon phase (no target URL)")
		return nil
	}

	started := ps.startPhase(ctx, SwarmPhaseRecon, true)
	// Reuse the swarm's probe-timeout knob if the operator tuned it; keep
	// the recon concurrency modest (8) regardless of the global probe
	// setting so a high --probe-concurrency value doesn't translate into
	// 50+ simultaneous GETs against a single recon target.
	reconTimeout := ps.cfg.ProbeTimeout
	if reconTimeout <= 0 {
		reconTimeout = 5 * time.Second
	}
	report, err := recon.Run(ctx, ps.targetURL, recon.Config{
		Concurrency:  8,
		Timeout:      reconTimeout,
		ExtraHeaders: ps.cfg.ReconExtraHeaders,
	})
	if err != nil {
		zap.L().Warn("Recon sweep failed, continuing without tech-stack context", zap.Error(err))
		ps.runner.addWarning(ps.result, "recon sweep failed: %v", err)
		ps.finishPhase(SwarmPhaseRecon, started)
		return nil
	}

	if report != nil && report.HasSignal() {
		ps.techStack = report
		if ps.sessionDir != "" {
			out, mErr := json.MarshalIndent(report, "", "  ")
			if mErr == nil {
				writeSessionArtifact(filepath.Join(ps.sessionDir, "recon-report.json"), out)
			}
		}
	}
	// Threshold >25%: a few 5xx/timeouts are normal, but a quarter of
	// the sweep failing is a network fault worth surfacing.
	if report != nil && report.ProbeCount > 0 {
		errRatio := float64(report.ProbeErrors) / float64(report.ProbeCount)
		if errRatio > 0.25 {
			ps.runner.addWarning(ps.result, "recon probe error rate high: %d/%d failed (%.0f%%) — partial tech-stack context",
				report.ProbeErrors, report.ProbeCount, errRatio*100)
		}
	}

	summary := recon.RenderConsoleSummary(report)
	ps.finishPhase(SwarmPhaseRecon, started)
	fmt.Fprintf(os.Stderr, "%s %s  %s\n",
		terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Recon"),
		terminal.Muted(summary+" in "+ps.phaseTimings[SwarmPhaseRecon].Round(time.Millisecond).String()))
	return nil
}

type planSwarmStep struct{}

func (planSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop {
		return nil
	}
	planRecords := selectPlanRecords(ps.records, ps.cfg.MaxPlanRecords)
	var recordSummary string
	if len(planRecords) < len(ps.records) {
		recordSummary = buildRecordSummary(ps.records)
		zap.L().Info("Filtered records for plan phase", zap.Int("total", len(ps.records)), zap.Int("selected", len(planRecords)))
		fmt.Fprintf(os.Stderr, "  %s Selected %s of %s records for planning (most interesting, summary of all included)\n",
			terminal.Cyan(terminal.SymbolBullet), terminal.Orange(fmt.Sprintf("%d", len(planRecords))), terminal.Orange(fmt.Sprintf("%d", len(ps.records))))
	}

	started := time.Now()
	techStackMd := recon.Render(ps.techStack)
	if ps.checkpoint != nil && phaseCompleted(ps.checkpoint, SwarmPhasePlan) && ps.checkpoint.Plan != nil {
		ps.plan = ps.checkpoint.Plan
		zap.L().Info("Restored plan from checkpoint", zap.Int("module_tags", len(ps.plan.ModuleTags)))
	} else {
		ps.startPhase(ctx, SwarmPhasePlan, true)
		var err error
		var masterRawOutput, masterRenderedPrompt string
		if len(planRecords) <= ps.cfg.MasterBatchSize {
			ps.plan, masterRawOutput, masterRenderedPrompt, err = ps.runner.runMasterAgent(ctx, ps.cfg, planRecords, ps.targetURL, techStackMd, recordSummary)
		} else {
			ps.plan, masterRawOutput, masterRenderedPrompt, ps.batchProv, err = ps.runner.runMasterAgentBatched(ctx, ps.cfg, planRecords, ps.targetURL, ps.cfg.MasterBatchSize, recordSummary, techStackMd)
		}
		writePromptToSessionDir(ps.sessionDir, "master-prompt.md", masterRenderedPrompt)
		if ps.sessionDir != "" && masterRawOutput != "" {
			writeSessionArtifact(filepath.Join(ps.sessionDir, "master-output.md"), []byte(masterRawOutput))
		}
		if err != nil {
			return fmt.Errorf("master agent failed: %w", err)
		}
		// runMasterAgent stamps ExtensionAgentError on the plan but
		// doesn't touch the result — bubble it up so operators see it
		// in coverage.json / the JSON output without grepping logs.
		if ps.plan != nil && ps.plan.ExtensionAgentError != "" {
			ps.runner.addWarning(ps.result, "extension agent failed (no custom extensions loaded): %s", ps.plan.ExtensionAgentError)
		}
	}
	// Coverage-feedback pass: when ≥2 URL-prefix clusters from the record
	// set aren't referenced by any FocusArea/Notes, fire one supplemental
	// plan call against just those clusters and merge.
	if ps.plan != nil && !ps.cfg.DryRun && !phaseCompleted(ps.checkpoint, SwarmPhasePlan) {
		coverage := AnalyzePlanCoverage(ps.plan, ps.records)
		const minMissingForSupplementalCall = 2
		if len(coverage.MissingPrefixes) >= minMissingForSupplementalCall {
			zap.L().Info("Coverage-feedback pass: prefixes lacking focus areas",
				zap.Int("missing", len(coverage.MissingPrefixes)),
				zap.Int("covered", coverage.CoveredPrefixes),
				zap.Int("total", coverage.TotalPrefixes),
				zap.Strings("missing_prefixes", coverage.MissingPrefixes))
			extraRecords := RecordsForPrefixes(ps.records, coverage.MissingPrefixes)
			const maxSupplementalRecords = 10
			extraSelected := selectPlanRecords(extraRecords, maxSupplementalRecords)
			if len(extraSelected) > 0 {
				supplementalPlan, suppRaw, _, suppErr := ps.runner.runMasterAgent(ctx, ps.cfg, extraSelected, ps.targetURL, techStackMd, "")
				if suppErr != nil {
					zap.L().Warn("Coverage-feedback supplemental plan failed; keeping original plan",
						zap.Error(suppErr))
					ps.runner.addWarning(ps.result, "coverage-feedback supplemental plan failed: %v", suppErr)
				} else if supplementalPlan != nil {
					mergedPlan, _ := mergeSwarmPlans([]*SwarmPlan{ps.plan, supplementalPlan})
					ps.plan = mergedPlan
					if ps.sessionDir != "" && suppRaw != "" {
						writeSessionArtifact(filepath.Join(ps.sessionDir, "master-supplemental-output.md"), []byte(suppRaw))
					}
					zap.L().Info("Coverage-feedback supplemental plan merged",
						zap.Int("new_focus_areas", len(supplementalPlan.FocusAreas)),
						zap.Int("new_module_tags", len(supplementalPlan.ModuleTags)),
						zap.Int("new_module_ids", len(supplementalPlan.ModuleIDs)))
				}
			}
		}
	}

	ps.phaseTimings[SwarmPhasePlan] = time.Since(started)
	ps.result.BatchProvenance = ps.batchProv
	ps.result.SwarmPlan = ps.plan
	if ps.plan != nil {
		batchSize := ps.cfg.MasterBatchSize
		if batchSize <= 0 {
			batchSize = 5
		}
		batches := 1
		if len(planRecords) > batchSize {
			batches = (len(planRecords) + batchSize - 1) / batchSize
		}
		stats := planPhaseStats{
			TotalRecords: len(ps.records),
			PlanRecords:  len(planRecords),
			Batches:      batches,
		}
		printPlanPhaseSummary(ps.cfg, ps.plan, ps.phaseTimings[SwarmPhasePlan], stats)
		planJSON, _ := json.Marshal(ps.plan)
		ps.agenticScan.AttackPlan = string(planJSON)
		if ps.sessionDir != "" {
			writeSessionArtifact(filepath.Join(ps.sessionDir, "swarm-plan.json"), planJSON)
		}
		ps.completedPhases = append(ps.completedPhases, SwarmPhasePlan)
		ps.writeCheckpoint(ps.plan, 0)
	}
	if ps.cfg.DryRun {
		ps.result.PhaseTimings = ps.phaseTimings
		ps.stop = true
	}
	return nil
}

// discoverReentrySwarmStep probes paths the planner mentioned but the
// crawler never saw, then ingests any responses into the record set + DB
// so the scan phase tests them. Capped at 8 paths to avoid runaway
// fan-out turning the swarm into a crawler-replacement.
type discoverReentrySwarmStep struct{}

func (discoverReentrySwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop || ps.cfg.DryRun || ps.plan == nil || ps.targetURL == "" {
		return nil
	}
	if PhaseSkipped(ps.cfg.SkipPhases, SwarmPhaseDiscover) {
		return nil
	}
	planPaths := extractPlanReferencedPaths(ps.plan)
	untested := filterUntestedPaths(planPaths, ps.records)
	const maxReentryURLs = 8
	urls := resolvePathsToURLs(ps.targetURL, untested, maxReentryURLs)
	if len(urls) == 0 {
		return nil
	}
	started := time.Now()
	pc := ps.cfg.probeConfig()
	probed := discoverReentryProbe(ctx, urls, pc)
	if len(probed) == 0 {
		zap.L().Debug("discoverReentry: probes returned nothing usable")
		return nil
	}
	zap.L().Info("Discovery re-entry probed planner-referenced paths",
		zap.Int("planner_paths", len(planPaths)),
		zap.Int("untested", len(untested)),
		zap.Int("probed", len(urls)),
		zap.Int("usable_responses", len(probed)))

	if ps.runner.repo != nil {
		for _, rr := range probed {
			if _, err := ps.runner.repo.SaveRecord(ctx, rr, RecordSourceDiscoverReentry, ps.cfg.ProjectUUID); err != nil {
				zap.L().Debug("discoverReentry: SaveRecord failed", zap.Error(err))
			}
		}
	}
	ps.records = deduplicateRecords(append(ps.records, probed...))
	ps.recordStats.Discovery += len(probed)
	ps.result.TotalRecords = len(ps.records)
	ps.phaseTimings[SwarmPhaseDiscoverReentry] = time.Since(started)
	return nil
}

type extensionSwarmStep struct{}

func (extensionSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop {
		return nil
	}
	started := time.Now()
	allExtensions, renames := ps.runner.buildSwarmExtensions(ctx, ps.cfg, ps.targetURL, ps.plan, ps.sourceExtensions)
	ps.extensionRenames = renames
	ps.extensionDir = ps.runner.persistSwarmExtensions(ctx, ps.cfg, ps.agenticScan, ps.sessionDir, ps.sourceExtensions, allExtensions)
	ps.phaseTimings[SwarmPhaseExtension] = time.Since(started)
	ps.completedPhases = append(ps.completedPhases, SwarmPhaseExtension)
	return nil
}

type scanSwarmStep struct{}

func (scanSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop || ps.cfg.ScanFunc == nil || phaseCompleted(ps.checkpoint, SwarmPhaseScan) {
		return nil
	}
	started := ps.startPhase(ctx, SwarmPhaseScan, true)
	scanReq := ScanRequest{ExtensionDir: ps.extensionDir}
	if ps.plan != nil {
		scanReq.ModuleTags = ps.plan.ModuleTags
		scanReq.ModuleIDs = ps.plan.ModuleIDs
	}
	if err := ps.cfg.ScanFunc(ctx, scanReq); err != nil {
		zap.L().Warn("Scan phase encountered an error, continuing with remaining phases", zap.Error(err))
		ps.runner.addWarning(ps.result, "scan phase encountered an error: %v", err)
		printPhaseLine(string(SwarmPhaseScan), fmt.Sprintf("scan error (non-fatal): %v", err))
	}
	ps.finishPhase(SwarmPhaseScan, started)
	if ps.runner.engine != nil {
		ps.runner.engine.InvalidateContextCache()
	}
	scanFindings := 0
	if ps.runner.repo != nil {
		counts, err := database.CountFindingsBySeverity(ctx, ps.runner.repo.DB(), ps.cfg.ProjectUUID)
		if err == nil {
			for _, c := range counts {
				scanFindings += int(c)
			}
		}
	}
	summary := fmt.Sprintf("completed — %d findings in %s", scanFindings, ps.phaseTimings[SwarmPhaseScan].Round(time.Second))
	if ps.extensionDir != "" {
		summary += " (custom extensions loaded)"
	}
	fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Native scan"), terminal.Muted(summary))
	ps.writeCheckpoint(ps.plan, 0)
	return nil
}

// replanOnEmptySwarmStep fires one business-logic-focused supplemental
// plan + rescan when the first scan turned up zero findings but recon
// flagged real surface. Skipped when scan produced findings, recon was
// empty, --triage=false, or in dry-run mode.
type replanOnEmptySwarmStep struct{}

func (replanOnEmptySwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop || ps.cfg.DryRun || ps.plan == nil || ps.cfg.ScanFunc == nil {
		return nil
	}
	if ps.runner.repo == nil {
		return nil
	}
	// Operators who silenced triage almost certainly don't want a second scan pass either.
	if PhaseSkipped(ps.cfg.SkipPhases, SwarmPhaseTriage) {
		return nil
	}
	counts, err := database.CountFindingsBySeverity(ctx, ps.runner.repo.DB(), ps.cfg.ProjectUUID)
	if err != nil {
		return nil
	}
	totalFindings := 0
	for _, c := range counts {
		totalFindings += int(c)
	}
	if totalFindings > 0 {
		return nil
	}
	if !replanWorthwhile(ps.techStack, ps.records) {
		zap.L().Debug("replanOnEmpty: skipping — no recon signal worth a second look")
		return nil
	}

	zap.L().Info("Scan produced zero findings but recon flagged real surface — running a business-logic-focused supplemental plan")
	started := time.Now()

	cfg := ps.cfg
	cfg.Focus = "behavioral and business-logic flaws — broken access control, race conditions, IDOR, privilege escalation, workflow tampering, mass assignment, authorization edge cases. Avoid duplicating signature-based modules already covered."
	techStackMd := recon.Render(ps.techStack)

	supplementalPlan, suppRaw, _, suppErr := ps.runner.runMasterAgent(ctx, cfg, selectPlanRecords(ps.records, 10), ps.targetURL, techStackMd, "")
	if suppErr != nil || supplementalPlan == nil {
		if suppErr != nil {
			zap.L().Warn("replanOnEmpty: supplemental plan failed", zap.Error(suppErr))
			ps.runner.addWarning(ps.result, "replan-on-empty supplemental plan failed: %v", suppErr)
		}
		return nil
	}
	mergedPlan, _ := mergeSwarmPlans([]*SwarmPlan{ps.plan, supplementalPlan})
	ps.plan = mergedPlan
	if ps.sessionDir != "" && suppRaw != "" {
		writeSessionArtifact(filepath.Join(ps.sessionDir, "master-replan-output.md"), []byte(suppRaw))
	}

	scanReq := ScanRequest{ExtensionDir: ps.extensionDir, ModuleTags: ps.plan.ModuleTags, ModuleIDs: ps.plan.ModuleIDs}
	if err := ps.cfg.ScanFunc(ctx, scanReq); err != nil {
		zap.L().Warn("replanOnEmpty: rescan failed", zap.Error(err))
		ps.runner.addWarning(ps.result, "replan-on-empty rescan failed: %v", err)
	}
	if ps.runner.engine != nil {
		ps.runner.engine.InvalidateContextCache()
	}
	ps.phaseTimings[SwarmPhaseReplanOnEmpty] = time.Since(started)
	return nil
}

// replanWorthwhile returns true when recon flagged something the first
// plan likely missed: detected stacks, API specs, login candidates,
// accepted non-GET methods, JS framework signals, or auth-bearing records.
func replanWorthwhile(report *recon.TechStackReport, records []*httpmsg.HttpRequestResponse) bool {
	if report != nil {
		if len(report.Stacks) > 0 || len(report.APISpecs) > 0 ||
			len(report.LoginCandidates) > 0 || len(report.MethodMatrix) > 0 ||
			len(report.JSSignals) > 0 {
			return true
		}
	}
	for _, rr := range records {
		if rr == nil || rr.Request() == nil {
			continue
		}
		if rr.Request().HasHeader("Authorization") || rr.Request().HasHeader("Cookie") {
			return true
		}
	}
	return false
}

type triageSwarmStep struct{}

func (triageSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop {
		return nil
	}
	if PhaseSkipped(ps.cfg.SkipPhases, SwarmPhaseTriage) {
		zap.L().Info("Skipping triage and rescan phases (--skip triage)")
		fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Triage"), terminal.Muted("skipped"))
		return nil
	}
	started := ps.startPhase(ctx, SwarmPhaseTriage, true)
	ps.completedPhases = append(ps.completedPhases, SwarmPhaseTriage)
	if err := ps.runner.runTriageLoop(ctx, ps.cfg, ps.agenticScan, ps.result, ps.sessionDir, ps.extensionDir, ps.checkpoint, ps.extensionRenames, ps.completedPhases); err != nil {
		zap.L().Warn("Triage failed, continuing with scan results", zap.Error(err))
		ps.runner.addWarning(ps.result, "triage failed: %v", err)
	}
	ps.phaseTimings[SwarmPhaseTriage] = time.Since(started)
	fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Triage"),
		terminal.Muted(fmt.Sprintf("completed — %d confirmed, %d false positives, %d iterations in %s",
			ps.result.Confirmed, ps.result.FalsePositives, ps.result.Iterations, ps.phaseTimings[SwarmPhaseTriage].Round(time.Second))))
	return nil
}

type finalizeSwarmStep struct{}

func (finalizeSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.runner.repo != nil {
		counts, err := database.CountFindingsBySeverity(ctx, ps.runner.repo.DB(), ps.cfg.ProjectUUID)
		if err == nil {
			total := 0
			sevCounts := make(map[string]int, len(counts))
			for sev, c := range counts {
				total += int(c)
				sevCounts[sev] = int(c)
			}
			ps.result.TotalFindings = total
			ps.result.SeverityCounts = sevCounts
		}
	}
	ps.result.PhaseTimings = ps.phaseTimings
	if ps.sessionDir != "" {
		byModule, byEndpoint := findingAggregatesFromDB(ctx, ps.runner.repo, ps.cfg.ProjectUUID)
		report := BuildSwarmCoverageReport(CoverageReportInputs{
			AgenticScanUUID:    ps.agenticScan.UUID,
			TargetURL:          ps.targetURL,
			Plan:               ps.plan,
			Records:            ps.records,
			TotalFindings:      ps.result.TotalFindings,
			FindingsByModule:   byModule,
			FindingsByEndpoint: byEndpoint,
			Warnings:           append([]string(nil), ps.result.Warnings...),
		})
		if path := WriteSwarmCoverageReport(ps.sessionDir, report); path != "" {
			zap.L().Info("Wrote coverage report", zap.String("path", path))
		}
		zap.L().Info("Agent session artifacts", zap.String("session_dir", ps.sessionDir))
	}
	return nil
}

func (s *SwarmRunner) buildSwarmExtensions(ctx context.Context, cfg SwarmConfig, targetURL string, plan *SwarmPlan, sourceExtensions []GeneratedExtension) ([]GeneratedExtension, map[string]string) {
	var allExtensions []GeneratedExtension
	var extensionRenames map[string]string
	if plan != nil {
		if len(plan.QuickChecks) > 0 {
			var validQCs []QuickCheck
			for _, qc := range plan.QuickChecks {
				hasErr := false
				for _, iss := range extensions.LintQuickCheck(qc) {
					if iss.Severity == "error" {
						hasErr = true
					}
				}
				if !hasErr {
					validQCs = append(validQCs, qc)
				}
			}
			plan.Extensions = append(plan.Extensions, extensions.GenerateQuickCheckExtensions(validQCs)...)
		}
		if len(plan.Snippets) > 0 {
			var validSnips []Snippet
			for _, snip := range plan.Snippets {
				hasErr := false
				for _, iss := range extensions.LintSnippet(snip) {
					if iss.Severity == "error" {
						hasErr = true
					}
				}
				if !hasErr {
					validSnips = append(validSnips, snip)
				}
			}
			plan.Extensions = append(plan.Extensions, extensions.GenerateSnippetExtensions(validSnips)...)
		}
		mergeResult := mergeExtensionsTracked(sourceExtensions, plan.Extensions)
		allExtensions = mergeResult.Extensions
		extensionRenames = mergeResult.Renames
	} else {
		allExtensions = sourceExtensions
	}

	preValidationCount := len(allExtensions)
	if preValidationCount == 0 {
		return allExtensions, extensionRenames
	}
	validExts, invalidExts := extensions.ValidateExtensionSyntax(allExtensions)
	allExtensions = validExts
	if len(invalidExts) > 0 {
		rc := RepairConfig{AgentName: cfg.AgentName, ShowPrompt: cfg.ShowPrompt, TargetURL: targetURL}
		if plan != nil {
			rc.FocusAreas = plan.FocusAreas
			rc.ModuleTags = plan.ModuleTags
		}
		repaired := RepairExtensionsWithLLM(ctx, s.engine, invalidExts, rc)
		if len(repaired) > 0 {
			validRepaired, _ := extensions.ValidateExtensionSyntax(repaired)
			allExtensions = append(allExtensions, validRepaired...)
		}
	}
	if len(allExtensions) == 0 && preValidationCount > 0 {
		fmt.Fprintf(os.Stderr, "%s All %d generated extensions failed syntax validation — scanning without custom extensions\n", terminal.WarningSymbol(), preValidationCount)
	}
	return allExtensions, extensionRenames
}

func (s *SwarmRunner) persistSwarmExtensions(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, sessionDir string, sourceExtensions, allExtensions []GeneratedExtension) string {
	if len(allExtensions) == 0 {
		return ""
	}
	s.emitPhase(cfg, SwarmPhaseExtension)
	agenticScan.CurrentPhase = SwarmPhaseExtension
	s.persistPhase(ctx, agenticScan)
	dir, err := writeExtensionsToDir(allExtensions, sessionDir)
	if err != nil {
		zap.L().Warn("Failed to write generated extensions", zap.Error(err))
		return ""
	}
	sourceExtCount := len(sourceExtensions)
	planExtCount := len(allExtensions) - sourceExtCount
	if planExtCount < 0 {
		planExtCount = 0
	}
	fmt.Fprintf(os.Stderr, "  %s Extensions: %s generated (source: %s, plan: %s)\n",
		terminal.Cyan(terminal.SymbolBullet),
		terminal.BoldYellow(fmt.Sprintf("%d", len(allExtensions))),
		terminal.Orange(fmt.Sprintf("%d", sourceExtCount)),
		terminal.Orange(fmt.Sprintf("%d", planExtCount)))
	for _, ext := range allExtensions {
		fmt.Fprintf(os.Stderr, "    %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(ext.Filename+":"), ext.Reason)
	}
	return dir
}

// planPhaseStats are runtime counters describing how many records reached each
// stage of the plan phase. Used by printPlanPhaseSummary to surface downscoping
// and batching decisions in the console output.
type planPhaseStats struct {
	TotalRecords int // total records after normalize/discovery
	PlanRecords  int // records actually fed to the plan agent (selectPlanRecords output)
	Batches      int // number of plan-agent batches that ran
}

// printPlanPhaseSummary renders the Plan-phase completion block, including the
// extension-decision line, a truncated reason, and contextual tips. The full
// reason and any extension-agent error remain in swarm-plan.json for forensics.
func printPlanPhaseSummary(cfg SwarmConfig, plan *SwarmPlan, elapsed time.Duration, stats planPhaseStats) {
	const reasonMaxWidth = 160

	extCount := len(plan.Extensions) + len(plan.QuickChecks) + len(plan.Snippets)
	header := fmt.Sprintf("completed — %d focus areas in %s",
		len(plan.FocusAreas), elapsed.Round(time.Second))
	if extCount > 0 {
		header = fmt.Sprintf("completed — %d focus areas, %d extensions in %s",
			len(plan.FocusAreas), extCount, elapsed.Round(time.Second))
	}
	fmt.Fprintf(os.Stderr, "%s %s  %s\n",
		terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Plan"), terminal.Muted(header))

	// Counters line — shown when downscoping or batching kicked in (or whenever
	// records came from the DB, where the user benefits from seeing the path).
	// Labels in HiTeal, numbers in BoldOrange so the metrics pop visually.
	if stats.TotalRecords > 0 && (stats.PlanRecords < stats.TotalRecords || stats.Batches > 1) {
		arrow := terminal.Muted("→")
		fmt.Fprintf(os.Stderr, "  %s %s %s  %s  %s %s  %s  %s %s\n",
			terminal.Cyan(terminal.SymbolBullet),
			terminal.HiTeal("Records:"), terminal.BoldOrange(fmt.Sprintf("%d", stats.TotalRecords)),
			arrow,
			terminal.HiTeal("Sampled:"), terminal.BoldOrange(fmt.Sprintf("%d", stats.PlanRecords)),
			arrow,
			terminal.HiTeal("Batches:"), terminal.BoldOrange(fmt.Sprintf("%d", stats.Batches)))
	}

	collapse := func(s string) string {
		s = strings.ReplaceAll(s, "\r\n", " ")
		s = strings.ReplaceAll(s, "\n", " ")
		return strings.TrimSpace(s)
	}
	reason := terminal.Truncate(collapse(plan.NeedsExtensionsReason), reasonMaxWidth)

	phase2Errored := plan.ExtensionAgentError != ""
	phase2Ran := cfg.ForceExtensions || plan.NeedsExtensions
	forcedOverride := cfg.ForceExtensions && !plan.NeedsExtensions

	// Emit "Extensions: <count> [<badge>] — <tail>" so the count and outcome
	// are scannable at a glance without reading the prose.
	printExt := func(symbol, count, badge, tail string) {
		fmt.Fprintf(os.Stderr, "  %s %s %s  %s",
			symbol,
			terminal.HiTeal("Extensions:"), terminal.BoldOrange(count),
			badge)
		if tail != "" {
			fmt.Fprintf(os.Stderr, "  %s", terminal.Muted("— "+tail))
		}
		fmt.Fprintln(os.Stderr)
	}

	switch {
	case !phase2Ran:
		// Case A: agent decided no, no override.
		printExt(terminal.Cyan(terminal.SymbolBullet), "0",
			terminal.Yellow("[skipped]"),
			"agent decided built-ins are sufficient")
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  %s Reason: %s\n", terminal.TipPrefix(), terminal.Gray(reason))
		}
		fmt.Fprintf(os.Stderr, "  %s pass %s to force the extension agent to run anyway\n",
			terminal.TipPrefix(), terminal.HiCyan("--with-extensions"))
		fmt.Fprintf(os.Stderr, "  %s pass %s to steer the planner toward custom checks\n",
			terminal.TipPrefix(), terminal.HiCyan("--instruction \"...\""))

	case phase2Errored:
		// Case C: requested but generation failed.
		printExt(terminal.WarningSymbol(), "0",
			terminal.Red("[failed]"),
			"generation errored, continuing without")
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  %s Reason: %s\n", terminal.TipPrefix(), terminal.Gray(reason))
		}
		errMsg := terminal.Truncate(collapse(plan.ExtensionAgentError), reasonMaxWidth)
		fmt.Fprintf(os.Stderr, "  %s Error: %s\n", terminal.TipPrefix(), terminal.Gray(errMsg))

	case forcedOverride:
		// Case D: --with-extensions overrode a "no" decision.
		printExt(terminal.Cyan(terminal.SymbolBullet), fmt.Sprintf("%d", extCount),
			terminal.HiCyan("[forced]"),
			"via --with-extensions (agent had said: no)")
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  %s Original reason: %s\n", terminal.TipPrefix(), terminal.Gray(reason))
		}

	default:
		// Case B: agent said yes, generation succeeded.
		printExt(terminal.Cyan(terminal.SymbolBullet), fmt.Sprintf("%d", extCount),
			terminal.Green("[generated]"),
			"agent flagged unusual surface")
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  %s Reason: %s\n", terminal.TipPrefix(), terminal.Gray(reason))
		}
	}
}
