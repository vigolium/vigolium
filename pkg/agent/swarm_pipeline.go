package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/backend"
	"github.com/vigolium/vigolium/pkg/agent/extensions"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
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

	agentRun *database.AgentRun
	result   *SwarmResult

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
	sessionID        string
	sessionIDs       []string
	batchProv        *BatchProvenance
	stop             bool
}

func (s *SwarmRunner) runSwarmPipeline(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult) error {
	state, cleanup, err := s.newSwarmPipelineState(ctx, cfg, agentRun, result)
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
		planSwarmStep{},
		extensionSwarmStep{},
		scanSwarmStep{},
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

func (s *SwarmRunner) newSwarmPipelineState(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult) (*swarmPipelineState, func(), error) {
	sessionDir := cfg.SessionDir
	if cfg.ResumeDir != "" {
		sessionDir = cfg.ResumeDir
	}
	if sessionDir == "" {
		var err error
		sessionDir, err = EnsureSessionDir(cfg.SessionsDir, agentRun.UUID)
		if err != nil {
			zap.L().Warn("Failed to create session dir, falling back to temp dirs", zap.Error(err))
		}
	}
	result.SessionDir = sessionDir
	cfg.SessionDir = sessionDir

	browserEnabled := s.engine != nil && s.engine.settings != nil && s.engine.settings.Agent.Browser.IsEnabled()
	CopySkillsToSessionDir(sessionDir, browserEnabled)

	var cleanup func()
	if _, wait, _ := startAuditAgentBackground(ctx, cfg.Archon, cfg.SourcePath, sessionDir, cfg.ProjectUUID, cfg.ScanUUID, "", s.repo, cfg.StreamWriter, func(msg string) {
		fmt.Fprintf(os.Stderr, "%s archon: %s\n", terminal.InfoSymbol(), msg)
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
		agentRun:     agentRun,
		result:       result,
		sessionDir:   sessionDir,
		checkpoint:   checkpoint,
		phaseTimings: make(map[string]time.Duration),
	}, cleanup, nil
}

func (ps *swarmPipelineState) startPhase(ctx context.Context, phase string, emit bool) time.Time {
	ps.agentRun.CurrentPhase = phase
	ps.runner.persistPhase(ctx, ps.agentRun)
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
		ps.agentRun.TargetURL = targetURL
	}
	ps.agentRun.InputType = string(ps.cfg.InputType)
	if ps.agentRun.InputType == "" && len(ps.cfg.Inputs) > 0 {
		ps.agentRun.InputType = string(agentinput.DetectInputType(ps.cfg.Inputs[0]))
	}

	recordUUIDs := ps.runner.validateProbeAndSave(ctx, ps.records, nil, nil, "agent-swarm", ps.cfg.ProjectUUID, ps.cfg.probeConfig())
	ps.agentRun.RecordCount = len(recordUUIDs)
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
	var sastRecords []*httpmsg.HttpRequestResponse
	var sastNotes []string
	var sastExtensions []GeneratedExtension
	var discoveredSessionConfig *AgentSessionConfig

	saCfg := SourceAnalysisConfig{
		AgentName:      ps.cfg.AgentName,
		TargetURL:      ps.targetURL,
		SourcePath:     ps.cfg.SourcePath,
		Files:          ps.cfg.Files,
		Instruction:    ps.cfg.Instruction,
		SessionKey:     SwarmPhaseSourceAnalysis,
		DryRun:         ps.cfg.DryRun,
		ShowPrompt:     ps.cfg.ShowPrompt,
		ScanUUID:       ps.cfg.ScanUUID,
		ProjectUUID:    ps.cfg.ProjectUUID,
		StreamWriter:   ps.cfg.StreamWriter,
		SessionDir:     ps.sessionDir,
		MaxConcurrency: ps.cfg.SAMaxConcurrency,
	}

	type saResultBundle struct {
		result         *SourceAnalysisResult
		rawOutput      string
		renderedPrompt string
	}
	saBundle, saErr := retryAgentCall(ctx, RetryConfig{MaxRetries: 1}, func(ctx context.Context, _ int) (saResultBundle, error) {
		r, raw, prompt, err := ps.runner.engine.RunSourceAnalysisParallel(ctx, saCfg)
		return saResultBundle{r, raw, prompt}, err
	})
	saResult := saBundle.result
	saRawOutput := saBundle.rawOutput
	saRenderedPrompt := saBundle.renderedPrompt

	writePromptToSessionDir(ps.sessionDir, "source-analysis-prompt.md", saRenderedPrompt)
	if ps.sessionDir != "" && saRawOutput != "" {
		outputPath := filepath.Join(ps.sessionDir, "source-analysis-output.md")
		_ = os.WriteFile(outputPath, []byte(saRawOutput), 0o644)
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
			vr := backend.ValidateSessionConfigDetailed(saResult.SessionConfig)
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
			loginRecords := backend.SessionConfigToHTTPRecords(saResult.SessionConfig)
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

	if ps.cfg.SASTFunc != nil {
		sastStarted := ps.startPhase(ctx, SwarmPhaseSAST, true)
		if err := ps.cfg.SASTFunc(ctx); err != nil {
			zap.L().Warn("SAST phase failed, continuing without SAST results", zap.Error(err))
			ps.runner.addWarning(ps.result, "sast phase failed: %v", err)
		} else {
			ps.finishPhase(SwarmPhaseSAST, sastStarted)
			ps.startPhase(ctx, SwarmPhaseSASTReview, true)
			sastReviewResult := ps.runner.runSASTReview(ctx, ps.cfg, ps.targetURL, ps.sessionDir)
			if sastReviewResult != nil {
				validatedRecords, validatedNotes := filterSourceRecordsByHostname(sastReviewResult.HTTPRecords, ps.targetURL)
				if len(validatedRecords) > 0 {
					printPhaseLine("source-analysis", fmt.Sprintf("appending SAST-review validated routes  count=%d", len(validatedRecords)))
					sastRecords = validatedRecords
					sastNotes = validatedNotes
				}
				sastExtensions = append(sastExtensions, sastReviewResult.Extensions...)
			}
			ps.finishPhase(SwarmPhaseSASTReview, time.Now())
		}
		if _, ok := ps.phaseTimings[SwarmPhaseSAST]; !ok {
			ps.finishPhase(SwarmPhaseSAST, sastStarted)
		}
	}

	ps.records = append(ps.records, saRecords...)
	ps.records = append(ps.records, sastRecords...)
	ps.result.TotalRecords = len(ps.records)
	ps.recordStats.Source = len(saRecords)
	ps.recordStats.SAST = len(sastRecords)
	ps.sourceExtensions = append(ps.sourceExtensions, saExtensions...)
	ps.sourceExtensions = append(ps.sourceExtensions, sastExtensions...)
	ps.runner.validateProbeAndSave(ctx, sastRecords, sastNotes, authHeaders, "agent-swarm-source", ps.cfg.ProjectUUID, ps.cfg.probeConfig())

	if ps.runner.repo != nil && ps.targetURL != "" {
		hostname := hostnameFromURL(ps.targetURL)
		if hostname != "" {
			ps.runner.reprobeUnprobedRecords(ctx, ps.cfg.ProjectUUID, hostname, authHeaders, "agent-swarm-source")
			ps.runner.reprobeUnprobedRecords(ctx, ps.cfg.ProjectUUID, hostname, authHeaders, "ast-grep")
		}
	}
	if len(saRecords) > 0 || len(sastRecords) > 0 {
		allRoutes := append(append([]*httpmsg.HttpRequestResponse{}, saRecords...), sastRecords...)
		printPhaseLine("source-analysis", fmt.Sprintf("%s routes discovered: %d (source-analysis: %d, sast: %d) %s",
			terminal.SymbolBullet, len(allRoutes), len(saRecords), len(sastRecords), formatRouteStatusSummary(allRoutes)))
	}
	if ps.sessionDir != "" && len(ps.sourceExtensions) > 0 {
		writeSourceExtensionsToSessionDir(ps.sourceExtensions, ps.sessionDir)
	}

	ps.finishPhase(SwarmPhaseSourceAnalysis, started)
	printPhaseLine("source-analysis", fmt.Sprintf("%s completed — %d routes, %d extensions in %s",
		terminal.SymbolSuccess, len(saRecords)+len(sastRecords), len(ps.sourceExtensions), ps.phaseTimings[SwarmPhaseSourceAnalysis].Round(time.Second)))
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
				rows := backend.AgentSessionConfigToSessionHostnames(discoveredSessionConfig, ps.cfg.ProjectUUID, ps.cfg.ScanUUID, hostname, "agent-swarm-source")
				if len(authHeaders) > 0 {
					now := time.Now()
					for _, r := range rows {
						r.HydratedAt = &now
					}
				}
				if len(rows) > 0 {
					if err := ps.runner.repo.SaveSessionHostnames(ctx, rows); err != nil {
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
			dbRows, err := ps.runner.repo.GetSessionHostnamesByHostname(ctx, ps.cfg.ProjectUUID, hostname)
			if err == nil && len(dbRows) > 0 {
				authHeaders = backend.AuthHeadersFromSessionHostnames(dbRows)
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
		backend.ReplaceAuthHeadersInHTTPRR(saRecords, authHeaders)
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
	if ps.checkpoint != nil && phaseCompleted(ps.checkpoint, SwarmPhasePlan) && ps.checkpoint.Plan != nil {
		ps.plan = ps.checkpoint.Plan
		zap.L().Info("Restored plan from checkpoint", zap.Int("module_tags", len(ps.plan.ModuleTags)))
	} else {
		ps.startPhase(ctx, SwarmPhasePlan, true)
		var err error
		var masterRawOutput, masterRenderedPrompt string
		if len(planRecords) <= ps.cfg.MasterBatchSize {
			ps.plan, ps.sessionID, masterRawOutput, masterRenderedPrompt, err = ps.runner.runMasterAgent(ctx, ps.cfg, planRecords, ps.targetURL, recordSummary)
		} else {
			ps.plan, ps.sessionID, masterRawOutput, masterRenderedPrompt, ps.sessionIDs, ps.batchProv, err = ps.runner.runMasterAgentBatched(ctx, ps.cfg, planRecords, ps.targetURL, ps.cfg.MasterBatchSize, recordSummary)
		}
		writePromptToSessionDir(ps.sessionDir, "master-prompt.md", masterRenderedPrompt)
		if ps.sessionDir != "" && masterRawOutput != "" {
			_ = os.WriteFile(filepath.Join(ps.sessionDir, "master-output.md"), []byte(masterRawOutput), 0o644)
		}
		if err != nil {
			return fmt.Errorf("master agent failed: %w", err)
		}
	}
	ps.phaseTimings[SwarmPhasePlan] = time.Since(started)
	ps.result.SessionID = ps.sessionID
	ps.result.SessionIDs = ps.sessionIDs
	ps.result.BatchProvenance = ps.batchProv
	ps.result.SwarmPlan = ps.plan
	if ps.plan != nil {
		extCount := len(ps.plan.Extensions) + len(ps.plan.QuickChecks) + len(ps.plan.Snippets)
		fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua("Plan"),
			terminal.Muted(fmt.Sprintf("completed — %d extensions, %d focus areas in %s", extCount, len(ps.plan.FocusAreas), ps.phaseTimings[SwarmPhasePlan].Round(time.Second))))
		ps.agentRun.SessionID = ps.sessionID
		planJSON, _ := json.Marshal(ps.plan)
		ps.agentRun.AttackPlan = string(planJSON)
		if ps.sessionDir != "" {
			_ = os.WriteFile(filepath.Join(ps.sessionDir, "swarm-plan.json"), planJSON, 0o644)
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

type extensionSwarmStep struct{}

func (extensionSwarmStep) Run(ctx context.Context, ps *swarmPipelineState) error {
	if ps.stop {
		return nil
	}
	started := time.Now()
	allExtensions, renames := ps.runner.buildSwarmExtensions(ctx, ps.cfg, ps.targetURL, ps.plan, ps.sourceExtensions)
	ps.extensionRenames = renames
	ps.extensionDir = ps.runner.persistSwarmExtensions(ctx, ps.cfg, ps.agentRun, ps.sessionDir, ps.sourceExtensions, allExtensions)
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
	if err := ps.runner.runTriageLoop(ctx, ps.cfg, ps.agentRun, ps.result, ps.sessionDir, ps.extensionDir, ps.checkpoint, ps.extensionRenames, ps.completedPhases); err != nil {
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

func (s *SwarmRunner) persistSwarmExtensions(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, sessionDir string, sourceExtensions, allExtensions []GeneratedExtension) string {
	if len(allExtensions) == 0 {
		return ""
	}
	s.emitPhase(cfg, SwarmPhaseExtension)
	agentRun.CurrentPhase = SwarmPhaseExtension
	s.persistPhase(ctx, agentRun)
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
